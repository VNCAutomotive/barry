///
/// \file	brawchannel.cc
///		Directs a named raw channel over STDIN/STDOUT
///

/*
    Copyright (C) 2010-2012, RealVNC Ltd.

        Some parts are inspired from bjavaloader.cc

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    See the GNU General Public License in the COPYING file at the
    root directory of this project for more details.
*/


#include <barry/barry.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <fstream>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <netinet/in.h>
#endif

#include "i18n.h"
#include "platform.h"
#include "barrygetopt.h"

using namespace std;
using namespace Barry;

// How long, in seconds, to wait between reads before checking if should shutdown
#define READ_TIMEOUT_SECONDS 1

#ifdef WIN32
#define INVALID_HANDLE ((HANDLE)NULL)
typedef SOCKET socket_t;
// This is a name of a public semaphore to signal when the listen socket is opened
#define LISTEN_SEMAPHORE_NAME _T("Barry_brawchannel_%s_%d_startup_rendezvous")
#define LISTEN_SEMAPHORE_MAX_LEN 255
#define LISTEN_ADDRESS_MAX 128
#else
#define INVALID_HANDLE -1
typedef int socket_t;
#endif

/* Defined generic stream reading and writing classes.
 *
 * It'd be great to use iostream, but they don't provide non-blocking reads.
 */
class Stream {
public:
	virtual ~Stream() {};
};

class InputStream {
public:
	virtual ~InputStream() {};
	virtual ssize_t read(unsigned char* ptr, size_t size, int timeout) = 0;
};

class OutputStream {
public:
	virtual ~OutputStream() {};
	virtual ssize_t write(const unsigned char* ptr, size_t size) = 0;
};

class StdOutStream : public OutputStream {
public:
	virtual ssize_t write(const unsigned char* ptr, size_t size);
};

ssize_t StdOutStream::write(const unsigned char* ptr, size_t size)
{
	size_t written = fwrite(ptr, 1, size, stderr);
	if( written == 0 &&
		( ferror(stderr) != 0 || feof(stderr) != 0 ) ) {
		return -1;
	}
	return static_cast<ssize_t>(written);
}


class StdInStream : public InputStream {
public:
	virtual ssize_t read(unsigned char* ptr, size_t size, int timeout);
};


#if defined(WIN32)
/* Windows terminal input class implementation */
ssize_t StdInStream::read(unsigned char* ptr, size_t size, int timeout)
{
	/* Windows CE can't do non-blocking IO, so just always fail to read anything*/
	Sleep(timeout * 1000);
	return 0;
}

#else
ssize_t StdInStream::read(unsigned char* ptr, size_t size, int timeout)
{
	fd_set rfds;
	struct timeval tv;
	FD_ZERO(&rfds);
	FD_SET(STDIN_FILENO, &rfds);
	tv.tv_sec = READ_TIMEOUT_SECONDS;
	tv.tv_usec = 0;
	int ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);
	if( ret < 0 ) {
		cerr << "Select failed with errno: " << errno << endl;
		return -1;
	} else if ( ret && FD_ISSET(STDIN_FILENO, &rfds) ) {
		return read(STDIN_FILENO, buf, bufSize);
	} else {
		return 0;
	}
}
#endif

class TcpStream : public Stream {
public:
	in_addr mHostAddress;
	const char * mListenAddress;
	long mPort;
	socket_t mListenSocket;
	socket_t mSocket;
#ifdef WIN32
	HANDLE mEvent;
	DWORD mWsaError;
#endif
public:
	TcpStream(const char * addr, long port);
	~TcpStream();
	bool accept();
};

class TcpInStream : public InputStream {
private:
	TcpStream& mStream;
public:
	TcpInStream(TcpStream& stream)
		: mStream(stream) {}
	virtual ssize_t read(unsigned char* ptr, size_t size, int timeout);
};

class TcpOutStream : public OutputStream {
private:
	TcpStream& mStream;
public:
	TcpOutStream(TcpStream& stream)
		: mStream(stream) {}
public:
	virtual ssize_t write(const unsigned char* ptr, size_t size);
};

TcpStream::TcpStream(const char * addr, long port)
: mListenAddress(addr)
, mPort(port)
, mListenSocket(INVALID_SOCKET)
, mSocket(INVALID_SOCKET)
{
#ifdef WIN32
	mEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	WSADATA wsaData;
	mWsaError = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if( mWsaError != 0 ) {
		cerr << "Failed to startup WSA: " << mWsaError << endl;
	}
#endif
	mListenSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if( mListenSocket == INVALID_SOCKET ) {
		cerr << "Failed to create listening socket: " << WSAGetLastError() << endl;
	}
	if( mListenAddress == NULL ) {
		mHostAddress.s_addr = INADDR_ANY;
	} else {
		mHostAddress.s_addr = inet_addr(mListenAddress);
	}
}

TcpStream::~TcpStream()
{
	if( mSocket != INVALID_SOCKET ) {
		shutdown(mSocket, SD_SEND);
		closesocket(mSocket);
		mSocket = INVALID_SOCKET;
	}
	if( mListenSocket != INVALID_SOCKET ) {
		shutdown(mListenSocket, SD_SEND);
		closesocket(mListenSocket);
		mListenSocket = INVALID_SOCKET;
	}
#ifdef WIN32
	if( mEvent != INVALID_HANDLE ) {
		CloseHandle(mEvent);
		mEvent = INVALID_HANDLE;
	}
	WSACleanup();
#endif
}

bool TcpStream::accept()
{
	if( mListenSocket == INVALID_SOCKET ||
		mWsaError != 0 || 
		mHostAddress.s_addr == INADDR_NONE ) {
		return false;
	}
	struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr = mHostAddress;
    serverAddr.sin_port = htons(static_cast<u_short>(mPort));
	if( ::bind(mListenSocket, (sockaddr*) & serverAddr, sizeof(serverAddr)) < 0 ) {
		cerr << "Failed to bind to listening address" << endl;
		return false;
	}

	// Set the socket options
	int one = 1;
	if( setsockopt(mListenSocket, SOL_SOCKET, SO_REUSEADDR,
		reinterpret_cast<const char *> (&one), sizeof(one)) < 0 ) {
		cerr << "Failed to enable reuse of address" << endl;
		return false;
	}

	ULONG longOne = 1;
	if( ioctlsocket(mListenSocket, FIONBIO, &longOne) == INVALID_SOCKET ) {
		cerr << "Failed to set non-blocking listening socket" << endl;
		return false;
	}

	if( ::listen(mListenSocket, 5) == INVALID_SOCKET ) {
		cerr << "Failed to listen to listening address" << endl;
		return false;
	}

	struct sockaddr_in clientAddr;
    int len = sizeof(clientAddr);
	cout << "Listening for connection on "
		<< string( mListenAddress == NULL ? "*" : mListenAddress )
		<< ":" << mPort << endl;

#ifdef WIN32
	/* Signal to a public semaphore that the listen socket is up */
	TCHAR wListenAddress[LISTEN_ADDRESS_MAX];
	if( MultiByteToWideChar(CP_ACP, 0,
			(mListenAddress == NULL ? "*" : mListenAddress), -1,
			wListenAddress, LISTEN_ADDRESS_MAX) > 0 ) {
		TCHAR semName[LISTEN_SEMAPHORE_MAX_LEN];
		_snwprintf(semName, LISTEN_SEMAPHORE_MAX_LEN, LISTEN_SEMAPHORE_NAME, wListenAddress, mPort);
		semName[LISTEN_SEMAPHORE_MAX_LEN - 1] = 0;
		HANDLE sem = CreateSemaphore(NULL, 0, 1, semName);
		if( sem != NULL ) {
			ReleaseSemaphore(sem, 1, NULL);
			CloseHandle(sem);
		}
	}

	int ret = WSAEventSelect(mListenSocket, mEvent, FD_ACCEPT);
	if( ret != 0 ) {
		cerr << "WSAEventSelect failed with error: " << ret << endl;
		return false;
	}
	DWORD signalledObj = WaitForSingleObject(mEvent, INFINITE);
	if( signalledObj != WAIT_OBJECT_0 ) {
		cerr << "Failed to wait for new connection: " << signalledObj << endl;
		return false;
	}
#else
#error TODO: non-win32 implementation
#endif

	mSocket = ::accept(mListenSocket, (struct sockaddr*) &clientAddr, &len);
	shutdown(mListenSocket, SD_SEND);
	closesocket(mListenSocket);
	mListenSocket = INVALID_SOCKET;
	if( mSocket == INVALID_SOCKET ) {
		cerr << "Failed to accept on listening socket" << endl;
		return false;
	}

	if( setsockopt(mSocket, IPPROTO_TCP, TCP_NODELAY,
		reinterpret_cast<const char *> (&one), sizeof(one)) < 0 ) {
		cerr << "Failed to set no delay" << endl;
		return false;
	}

	return true;
}

#ifdef WIN32
ssize_t TcpInStream::read(unsigned char* ptr, size_t size, int timeout)
{
	int ret = WSAEventSelect(mStream.mSocket, mStream.mEvent, FD_READ);
	if( ret != 0 ) {
		cerr << "WSAEventSelect failed with error: " << ret << endl;
		return -1;
	}
	switch( WaitForSingleObject(mStream.mEvent, timeout * 1000) ) {
		case WAIT_ABANDONED:
		case WAIT_TIMEOUT:
			return 0;
		case WAIT_OBJECT_0:
			ResetEvent(mStream.mEvent);
			ret = ::recv(mStream.mSocket, reinterpret_cast<char *>(ptr), size, 0);
			if( ret == SOCKET_ERROR ) {
				int wsaErr = WSAGetLastError();
				switch( wsaErr ) {
				case WSAEWOULDBLOCK:
					return 0;
				default:
					return -1;
				}
			} else {
				return ret;
			}
		case WAIT_FAILED:
		default:
			cerr << "WaitForSingleObject failed with error: " << GetLastError() << endl;
			return -1;
	};
}

#else
ssize_t TcpInStream::read(unsigned char* ptr, size_t size, int timeout)
{
	fd_set rfds;
	struct timeval tv;
	FD_ZERO(&rfds);
	FD_SET(mStream.mSocket, &rfds);
	tv.tv_sec = READ_TIMEOUT_SECONDS;
	tv.tv_usec = 0;
	int ret = select(mStream.mSocket + 1, &rfds, NULL, NULL, &tv);
	if( ret < 0 ) {
		cerr << "Select failed with errno: " << errno << endl;
		return -1;
	} else if ( ret && FD_ISSET(mStream.mSocket, &rfds) ) {
		return ::recv(mStream.mSocket, reinterpret_cast<char *>(ptr), size, 0);
	} else {
		return 0;
	}
}
#endif

ssize_t TcpOutStream::write(const unsigned char* ptr, size_t size)
{
	return ::send(mStream.mSocket, reinterpret_cast<const char*>(ptr), size, 0);
}

static volatile bool signalReceived = false;

static void signalHandler(int signum)
{
	signalReceived = true;
}

class CallbackHandler : public Barry::Mode::RawChannelDataCallback
{
private:
	OutputStream& m_output;
	volatile bool *m_continuePtr;
	bool m_verbose;

public:
	CallbackHandler(OutputStream& output, volatile bool &keepGoing, bool verbose)
		: m_output(output)
		, m_continuePtr(&keepGoing)
		, m_verbose(verbose)
		{
		}


public: // From RawChannelDataCallback
	virtual void DataReceived(Data &data);
	virtual void ChannelError(string msg);
	virtual void ChannelClose();
};


void CallbackHandler::DataReceived(Data &data)
{
	if( m_verbose ) {
		cerr << "From BB: ";
		data.DumpHex(cerr);
		cerr << "\n";
	}

	size_t toWrite = data.GetSize();
	size_t written = 0;

	while( written < toWrite && *m_continuePtr ) {
		ssize_t writtenThisTime = m_output.write(&(data.GetData()[written]), toWrite - written);
		if( m_verbose ) {
			cerr.setf(ios::dec, ios::basefield);
			cerr << "Written " << writtenThisTime << " bytes over stdout" << endl;
		}
		fflush(stdout);
		if( writtenThisTime < 0 ) {
			ChannelClose();
		}
		else {
			written += writtenThisTime;
		}
	}
}

void CallbackHandler::ChannelError(string msg)
{
	cerr << "CallbackHandler: Received error: " << msg << endl;
	ChannelClose();
}

void CallbackHandler::ChannelClose()
{
	*m_continuePtr = false;
}

void Usage()
{
	int logical, major, minor;
	const char *Version = Barry::Version(logical, major, minor);

	cerr
		<< "brawchannel - Command line USB Blackberry raw channel interface\n"
		<< "        Copyright 2010, RealVNC Ltd.\n"
		<< "        Using: " << Version << "\n"
		<< "\n"
		<< "Usage:\n"
		<< "brawchannel [options] <channel name>\n"
		<< "\n"
		<< "   -h        This help\n"
		<< "   -p pin    PIN of device to talk with\n"
		<< "             If only one device is plugged in, this flag is optional\n"
		<< "   -P pass   Simplistic method to specify device password\n"
		<< "   -l port   Listen for a TCP connection on the provided port instead\n"
		<< "             of using STDIN and STDOUT for data\n"
		<< "   -a addr   Address to bind the listening socket to, allowing listening\n"
		<< "             only on a specified interface\n"
		<< "   -v        Dump protocol data during operation\n"
		<< "             This will cause libusb output to appear on STDOUT unless\n"
		<< "             the environment variable USB_DEBUG is set to 0,1 or 2.\n"
		<< endl;
}

// Helper class to restore signal handlers when shutdown is occuring
// This class isn't responsible for setting up the signal handlers
// as they need to be restored before the Barry::Socket starts closing.
class SignalRestorer
{
private:
	int m_signum;
	sighandler_t m_handler;
public:
	SignalRestorer(int signum, sighandler_t handler)
		: m_signum(signum), m_handler(handler) {}
	~SignalRestorer() { signal(m_signum, m_handler); }
};

int main(int argc, char *argv[])
{
	INIT_I18N(PACKAGE);

	// Setup signal handling
	sighandler_t oldSigHup = signal(SIGHUP, &signalHandler);
	sighandler_t oldSigTerm = signal(SIGTERM, &signalHandler);
	sighandler_t oldSigInt = signal(SIGINT, &signalHandler);
	sighandler_t oldSigQuit = signal(SIGQUIT, &signalHandler);

	cerr.sync_with_stdio(true);	// since libusb uses
					// stdio for debug messages

	// Buffer to hold data read in from STDIN before sending it
	// to the BlackBerry.
	unsigned char *buf = NULL;
	try {
		uint32_t pin = 0;
		bool data_dump = false;
		string password;
		char * tcp_addr = NULL;
		long tcp_port = 0;

		// process command line options
		for( ;; ) {
			int cmd = getopt(argc, argv, "hp:P:l:a:v");
			if( cmd == -1 ) {
				break;
			}

			switch( cmd )
			{
			case 'p':	// Blackberry PIN
				pin = strtoul(optarg, NULL, 16);
				break;

			case 'P':	// Device password
				password = optarg;
				break;

			case 'v':	// data dump on
				data_dump = true;
				break;

			case 'l':
				tcp_port = strtol(optarg, NULL, 10);
				break;

			case 'a':
				tcp_addr = optarg;
				break;

			case 'h':	// help
			default:
				Usage();
			return 0;
			}
		}

		argc -= optind;
		argv += optind;

		if( argc < 1 ) {
			cerr << "Error: Missing raw channel name." << endl;
			Usage();
			return 1;
		}

		if( argc > 1 ) {
			cerr << "Error: Too many arguments." << endl;
			Usage();
			return 1;
		}

		// Fetch command from remaining arguments
		string channelName = argv[0];
		argc --;
		argv ++;

		if( tcp_addr != NULL && tcp_port == 0 ) {
			cerr << "Error: specified TCP listen address but no port." << endl;
			return 1;
		}

		if( data_dump ) {
			// Warn if USB_DEBUG isn't set to 0, 1 or 2
			// as that usually means libusb will write to STDOUT
			char *val = getenv("USB_DEBUG");
			int parsedValue = -1;
			if( val ) {
				parsedValue = atoi(val);
			}
			if( parsedValue != 0 && parsedValue != 1 && parsedValue != 2 ) {
				cerr << "Warning: Protocol dump enabled without setting USB_DEBUG to 0, 1 or 2.\n"
				     << "         libusb might log to STDOUT and ruin data stream." << endl;
			}
		}

		// Initialize the barry library.  Must be called before
		// anything else.
		Barry::Init(data_dump, &cerr);

		// Probe the USB bus for Blackberry devices.
		// If user has specified a PIN, search for it in the
		// available device list here as well
		Barry::Probe probe;
		int activeDevice = probe.FindActive(pin);
		if( activeDevice == -1 ) {
			cerr << "No device selected, or PIN not found" << endl;
			return 1;
		}

		// Now get setup to open the channel.
		if( data_dump ) {
			cerr << "Connected to device, starting read/write\n";
		}

		volatile bool running = true;

		auto_ptr<TcpStream> tcpStreamPtr;
		auto_ptr<InputStream> inputPtr;
		auto_ptr<OutputStream> outputPtr;
		
		if( tcp_port != 0 ) {
			/* Use TCP socket for channel data */
			tcpStreamPtr.reset(new TcpStream(tcp_addr, tcp_port));
			if( !tcpStreamPtr->accept() )
				return 1;
			inputPtr.reset(new TcpInStream(*tcpStreamPtr));
			outputPtr.reset(new TcpOutStream(*tcpStreamPtr));
		} else {
			/* Use STDIN and STDOUT for channel data */
			inputPtr.reset(new StdInStream());
			outputPtr.reset(new StdOutStream());
		}
		// Create the thing which will write onto stdout
		// and perform other callback duties.
		CallbackHandler callbackHandler(*outputPtr, running, data_dump);

		// Start a thread to handle any data arriving from
		// the BlackBerry.
		auto_ptr<SocketRoutingQueue> router;
		router.reset(new SocketRoutingQueue());
		router->SpinoffSimpleReadThread();

		// Create our controller object
		Barry::Controller con(probe.Get(activeDevice), *router);

		Barry::Mode::RawChannel rawChannel(con, callbackHandler);

		// Try to open the requested channel now everything is setup
		rawChannel.Open(password.c_str(), channelName.c_str());

		// We now have a thread running to read from the
		// BB and write over stdout; in this thread we'll
		// read from stdin and write to the BB.
		const size_t bufSize = rawChannel.MaximumSendSize();
		buf = new unsigned char[bufSize];

		// Set up the signal restorers to restore signal
		// handling (in their destructors) before the socket
		// starts to be closed. This allows, for example,
		// double control-c presses to stop graceful close
		// down.
		SignalRestorer srh(SIGHUP, oldSigHup);
		SignalRestorer srt(SIGTERM, oldSigTerm);
		SignalRestorer sri(SIGINT, oldSigInt);
		SignalRestorer srq(SIGQUIT, oldSigQuit);

		while( running && !signalReceived ) {
			ssize_t haveRead = inputPtr->read(buf, bufSize, READ_TIMEOUT_SECONDS);
			if( haveRead > 0 ) {
				Data toWrite(buf, haveRead);
				if( data_dump ) {
					cerr.setf(ios::dec, ios::basefield);
					cerr << "Sending " << haveRead << " bytes stdin->USB\n";
					cerr << "To BB: ";
					toWrite.DumpHex(cerr);
					cerr << "\n";
				}
				rawChannel.Send(toWrite);
				if( data_dump ) {
					cerr.setf(ios::dec, ios::basefield);
					cerr << "Sent " << haveRead << " bytes stdin->USB\n";
				}
			}
			else if( haveRead < 0 ) {
				running = false;
			}
		}
	}
	catch( const Usb::Error &ue ) {
		cerr << "Usb::Error caught: " << ue.what() << endl;
		return 1;
	}
	catch( const Barry::Error &se ) {
		cerr << "Barry::Error caught: " << se.what() << endl;
		return 1;
	}
	catch( const exception &e ) {
		cerr << "exception caught: " << e.what() << endl;
		return 1;
	}
	catch( ... ) {
		cerr << "unknown exception caught" << endl;
		return 1;
	}

	delete[] buf;

	return 0;
}

