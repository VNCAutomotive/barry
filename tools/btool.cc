///
/// \file	btool.cc
///		Barry library tester
///

/*
    Copyright (C) 2005-2012, Net Direct Inc. (http://www.netdirect.ca/)

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

//
// This define is used in barry/barry.h to signal inclusion of Boost
// serialization headers.  It is intended to be used by applications,
// so we shouldn't mess with it.
//
// But all actual Boost related code is now stuffed into util.cc, safely
// locked away from other code.  So we don't need the Boost headers, we
// just need a flag for our own functionality.  So translate this define
// into our own, and undef to skip the Boost headers, and the compile speed
// slowdown that it creates.
//
#ifdef __BARRY_BOOST_MODE__
#define __BTOOL_BOOST_MODE__
#endif
#undef __BARRY_BOOST_MODE__

#include <barry/barry.h>
#ifdef __BARRY_SYNC_MODE__
#include <barry/barrysync.h>
#endif
#ifdef __BARRY_BACKUP_MODE__
#include <barry/barrybackup.h>
#endif

#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <stdlib.h>
#include "i18n.h"
#include "util.h"
#include "boostwrap.h"

#include "barrygetopt.h"

using namespace std;
using namespace Barry;
using namespace Barry::tr1;

std::map<std::string, std::string> SortKeys;

void Usage()
{
   int logical, major, minor;
   const char *Version = Barry::Version(logical, major, minor);

   cerr
   << "btool - Command line USB Blackberry Test Tool\n"
   << "        Copyright 2005-2012, Net Direct Inc. (http://www.netdirect.ca/)\n"
   << "        Using: " << Version << "\n"
   << "        Compiled "
#ifdef __BTOOL_BOOST_MODE__
   << "with"
#else
   << "without"
#endif
   << " Boost support\n"
   << "\n"
   << "   -b file   Filename to save or load a Barry Backup to (tar.gz)\n"
   << "   -B bus    Specify which USB bus to search on\n"
   << "   -N dev    Specify which system device, using system specific string\n"
   << "\n"
   << "   -a db     Erase / clear database 'db' FROM device, deleting all\n"
   << "             its records.  Can be used multiple times to clear more\n"
   << "             than one DB.\n"
   << "   -c dn     Convert address book database to LDIF format, using the\n"
   << "             specified baseDN\n"
   << "   -C dnattr LDIF attribute name to use when building the FQDN\n"
   << "             Defaults to 'cn'\n"
   << "   -d db     Load database 'db' FROM device and dump to screen\n"
   << "             Can be used multiple times to fetch more than one DB\n"
   << "   -e epp    Override endpoint pair detection.  'epp' is a single\n"
   << "             string separated by a comma, holding the read,write\n"
   << "             endpoint pair.  Example: -e 83,5\n"
   << "             Note: Endpoints are specified in hex.\n"
   << "             You should never need to use this option.\n"
#ifdef __BTOOL_BOOST_MODE__
   << "   -f file   Filename to save or load handheld data to/from\n"
#endif
   << "   -F sort   Field name by which to sort the output.  Note that the\n"
   << "             format of this field is special: 'DBName:field1,field2'\n"
   << "             with no spaces unless the spaces are part of the name.\n"
   << "             Can be used multiple times, to match your -d options.\n"
   << "             Example: -F 'Address Book:Company,LastName,FirstName'\n"
   << "   -h        This help\n"
   << "   -i cs     International charset for string conversions\n"
   << "             Valid values here are available with 'iconv --list'\n"
   << "   -I        Sort records before output\n"
   << "   -l        List devices\n"
   << "   -L        List Contact field names\n"
   << "   -m        Map LDIF name to Contact field / Unmap LDIF name\n"
   << "                Map: ldif,read,write - maps ldif to read/write Contact fields\n"
   << "                Unmap: ldif name alone\n"
   << "   -M        List current LDIF mapping\n"
   << "   -n        Use null parser on all databases.\n"
   << "   -p pin    PIN of device to talk with\n"
   << "             If only one device is plugged in, this flag is optional\n"
   << "   -P pass   Simplistic method to specify device password\n"
   << "   -s db     Save database 'db' TO device from data loaded from -f file\n"
   << "   -S        Show list of supported database parsers.  Use twice to\n"
   << "             display fields names as well.\n"
   << "   -t        Show database database table\n"
   << "   -T db     Show record state table for given database\n"
   << "   -v        Dump protocol data during operation\n"
#ifdef __BARRY_SYNC_MODE__
   << "   -V        Dump records using MIME vformats where possible\n"
#endif
   << "   -X        Reset device\n"
   << "   -z        Use non-threaded sockets\n"
   << "   -Z        Use threaded socket router (default)\n"
   << "\n"
   << " -d Command modifiers:   (can be used multiple times for more than 1 record)\n"
   << "\n"
   << "   -r #      Record index number as seen in the -T state table.\n"
   << "             This overrides the default -d behaviour, and only\n"
   << "             downloads the one specified record, sending to stdout.\n"
   << "   -R #      Same as -r, but also clears the record's dirty flags.\n"
   << "   -D #      Record index number as seen in the -T state table,\n"
   << "             which indicates the record to delete.  Used with the -d\n"
   << "             command to specify the database.\n"
   << endl;
}

class Contact2Ldif
{
public:
	Barry::ContactLdif &ldif;

	Contact2Ldif(Barry::ContactLdif &ldif) : ldif(ldif) {}

	void operator()(const Contact &rec)
	{
		ldif.DumpLdif(cout, rec);
	}
};

template <class Record>
struct Store
{
	std::vector<Record> records;
	mutable typename std::vector<Record>::const_iterator rec_it;
	std::string filename;
	bool load;
	bool immediate_display;
	bool vformat_mode;
	int from_device_count;
	mutable int to_device_count;

	Store(const string &filename, bool load, bool immediate_display,
			bool vformat_mode)
		: rec_it(records.end()),
		filename(filename),
		load(load),
		immediate_display(immediate_display && !SortKeys.size()),
		vformat_mode(vformat_mode),
		from_device_count(0),
		to_device_count(0)
	{
#ifdef __BTOOL_BOOST_MODE__
		if( load && filename.size() ) {
			// filename is available, attempt to load
			cout << "Loading: " << filename << endl;
			string errmsg, dbName;
			if( !LoadBoostFile(filename, records, dbName, errmsg) ) {
				cerr << errmsg << endl;
			}
			cout << records.size()
			     << " records loaded from '"
			     << filename << "'" << endl;
			sort(records.begin(), records.end());
			rec_it = records.begin();

			// debugging aid
			typename std::vector<Record>::const_iterator beg = records.begin(), end = records.end();
			for( ; beg != end; beg++ ) {
				cout << (*beg) << endl;
			}
		}
#endif
	}

	~Store()
	{
		if( !immediate_display ) {
			// not dumped yet, sort then dump
			if( SortKeys.size() && SortKeys.find(Record::GetDBName()) != SortKeys.end() ) {
				sort(records.begin(), records.end(),
					NamedFieldCmp<Record>(SortKeys[Record::GetDBName()]));
			}
			else {
				sort(records.begin(), records.end());
			}
			DumpAll();
		}

		cout << "Store counted " << dec << from_device_count << " records read from device, and " << dec << to_device_count << " records written to device." << endl;
#ifdef __BTOOL_BOOST_MODE__
		if( !load && filename.size() ) {
			// filename is available, attempt to save
			cout << "Saving: " << filename << endl;
			string errmsg;
			if( !SaveBoostFile(filename, records, errmsg) ) {
				cerr << errmsg << endl;
			}
			cout << dec << records.size() << " records saved to '"
				<< filename << "'" << endl;
		}
#endif
	}

	void DumpAll()
	{
		typename vector<Record>::const_iterator i = records.begin();
		for( ; i != records.end(); ++i ) {
			Dump(*i);
		}
	}

	void Dump(const Record &rec)
	{
		if( vformat_mode ) {
#ifdef __BARRY_SYNC_MODE__
			MimeDump<Record> md;
			md.Dump(cout, rec);
#endif
		}
		else {
			cout << rec << endl;
		}
	}

	// storage operator
	void operator()(const Record &rec)
	{
		from_device_count++;
		if( immediate_display )
			Dump(rec);
		records.push_back(rec);
	}

	// retrieval operator
	bool operator()(Record &rec, Builder &builder) const
	{
		if( rec_it == records.end() )
			return false;
		to_device_count++;
		rec = *rec_it;
		rec_it++;
		return true;
	}
};

shared_ptr<Parser> GetParser(const string &name,
			const string &filename,
			bool null_parser,
			bool immediate_display,
			bool vformat_mode,
			bool bbackup_mode)
{
	bool dnow = immediate_display;
	bool vmode = vformat_mode;

	if( null_parser ) {
		// use null parser
		return shared_ptr<Parser>( new Barry::HexDumpParser(cout) );
	}
	else if( bbackup_mode ) {
#ifdef __BARRY_BACKUP_MODE__
		// Only one backup file per run
		static shared_ptr<Parser> backup;
		if( !backup.get() ) {
			backup.reset( new Backup(filename) );
		}
		return backup;
#else
		return shared_ptr<Parser>( new Barry::HexDumpParser(cout) );
#endif
	}
	// check for recognized database names
	else if( name == Contact::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<Contact, Store<Contact> > (
				new Store<Contact>(filename, false, dnow, vmode)));
	}
	else if( name == Message::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<Message, Store<Message> > (
				new Store<Message>(filename, false, dnow, vmode)));
	}
	else if( name == Calendar::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<Calendar, Store<Calendar> > (
				new Store<Calendar>(filename, false, dnow, vmode)));
	}
	else if( name == CalendarAll::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<CalendarAll, Store<CalendarAll> > (
				new Store<CalendarAll>(filename, false, dnow, vmode)));
	}
	else if( name == CallLog::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<CallLog, Store<CallLog> > (
				new Store<CallLog>(filename, false, dnow, vmode)));
	}
	else if( name == Bookmark::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<Bookmark, Store<Bookmark> > (
				new Store<Bookmark>(filename, false, dnow, vmode)));
	}
	else if( name == ServiceBook::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<ServiceBook, Store<ServiceBook> > (
				new Store<ServiceBook>(filename, false, dnow, vmode)));
	}

	else if( name == Memo::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<Memo, Store<Memo> > (
				new Store<Memo>(filename, false, dnow, vmode)));
	}
	else if( name == Task::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<Task, Store<Task> > (
				new Store<Task>(filename, false, dnow, vmode)));
	}
	else if( name == PINMessage::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<PINMessage, Store<PINMessage> > (
				new Store<PINMessage>(filename, false, dnow, vmode)));
	}
	else if( name == SavedMessage::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<SavedMessage, Store<SavedMessage> > (
				new Store<SavedMessage>(filename, false, dnow, vmode)));
	}
	else if( name == Sms::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<Sms, Store<Sms> > (
				new Store<Sms>(filename, false, dnow, vmode)));
	}
	else if( name == Folder::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<Folder, Store<Folder> > (
				new Store<Folder>(filename, false, dnow, vmode)));
	}
	else if( name == TimeZone::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<TimeZone, Store<TimeZone> > (
				new Store<TimeZone>(filename, false, dnow, vmode)));
	}
	else if( name == HandheldAgent::GetDBName() ) {
		return shared_ptr<Parser>(
			new RecordParser<HandheldAgent, Store<HandheldAgent> > (
				new Store<HandheldAgent>(filename, false, dnow, vmode)));
	}
	else {
		// unknown database, use null parser
		return shared_ptr<Parser>( new Barry::HexDumpParser(cout) );
	}
}

shared_ptr<Builder> GetBuilder(const string &name, const string &filename)
{
	// check for recognized database names
	if( name == Contact::GetDBName() ) {
		return shared_ptr<Builder>(
			new RecordBuilder<Contact, Store<Contact> > (
				new Store<Contact>(filename, true, true, false)));
	}
	else if( name == Calendar::GetDBName() ) {
		return shared_ptr<Builder>(
			new RecordBuilder<Calendar, Store<Calendar> > (
				new Store<Calendar>(filename, true, true, false)));
	}
	else if( name == CalendarAll::GetDBName() ) {
		return shared_ptr<Builder>(
			new RecordBuilder<CalendarAll, Store<CalendarAll> > (
				new Store<CalendarAll>(filename, true, true, false)));
	}
	else if( name == Memo::GetDBName() ) {
		return shared_ptr<Builder>(
			new RecordBuilder<Memo, Store<Memo> > (
				new Store<Memo>(filename, true, true, false)));
	}
	else if( name == Task::GetDBName() ) {
		return shared_ptr<Builder>(
			new RecordBuilder<Task, Store<Task> > (
				new Store<Task>(filename, true, true, false)));
	}
/*
	else if( name == "Messages" ) {
		return shared_ptr<Parser>(
			new RecordParser<Message, Store<Message> > (
				new Store<Message>(filename, true, true, false)));
	}
	else if( name == "Service Book" ) {
		return shared_ptr<Parser>(
			new RecordParser<ServiceBook, Store<ServiceBook> > (
				new Store<ServiceBook>(filename, true, true, false)));
	}
*/
	else {
		throw std::runtime_error("No Builder available for database");
	}
}

struct StateTableCommand
{
	char flag;
	bool clear;
	unsigned int index;

	StateTableCommand(char f, bool c, unsigned int i)
		: flag(f), clear(c), index(i) {}
};

bool SplitMap(const string &map, string &ldif, string &read, string &write)
{
	string::size_type a = map.find(',');
	if( a == string::npos )
		return false;

	string::size_type b = map.find(',', a+1);
	if( b == string::npos )
		return false;

	ldif.assign(map, 0, a);
	read.assign(map, a + 1, b - a - 1);
	write.assign(map, b + 1, map.size() - b - 1);

	return ldif.size() && read.size() && write.size();
}

void DoMapping(ContactLdif &ldif, const vector<string> &mapCommands)
{
	for(	vector<string>::const_iterator i = mapCommands.begin();
		i != mapCommands.end();
		++i )
	{
		// single names mean unmapping
		if( i->find(',') == string::npos ) {
			// unmap
			cerr << "Unmapping: " << *i << endl;
			ldif.Unmap(*i);
		}
		else {
			cerr << "Mapping: " << *i << endl;

			// map... extract ldif/read/write names
			string ldifname, read, write;
			if( SplitMap(*i, ldifname, read, write) ) {
				if( !ldif.Map(ldifname, read, write) ) {
					cerr << "Read/Write name unknown: " << *i << endl;
				}
			}
			else {
				cerr << "Invalid map format: " << *i << endl;
			}
		}
	}
}

bool ParseEpOverride(const char *arg, Usb::EndpointPair *epp)
{
	int read, write;
	char comma;
	istringstream iss(arg);
	iss >> hex >> read >> comma >> write;
	if( !iss )
		return false;
	epp->read = read;
	epp->write = write;
	return true;
}

void ParseSortKey(const std::string &key)
{
	istringstream iss(key);
	string db, spec;
	getline(iss, db, ':');
	getline(iss, spec, ':');

	if( db.size() && spec.size() )
		SortKeys[db] = spec;
}

int main(int argc, char *argv[])
{
	INIT_I18N(PACKAGE);

	cout.sync_with_stdio(true);	// leave this on, since libusb uses
					// stdio for debug messages

	try {

		uint32_t pin = 0;
		bool	list_only = false,
			show_dbdb = false,
			ldif_contacts = false,
			data_dump = false,
			vformat_mode = false,
			reset_device = false,
			list_contact_fields = false,
			list_ldif_map = false,
			epp_override = false,
			threaded_sockets = true,
			record_state_table = false,
			clear_database = false,
			null_parser = false,
			bbackup_mode = false,
			sort_records = false,
			show_parsers = false,
			show_fields = false;
		string ldifBaseDN, ldifDnAttr;
		string filename;
		string password;
		string busname;
		string devname;
		string iconvCharset;
		vector<string> dbNames, saveDbNames, mapCommands, clearDbNames;
		vector<StateTableCommand> stCommands;
		Usb::EndpointPair epOverride;

		// process command line options
		for(;;) {
			int cmd = getopt(argc, argv, "a:b:B:c:C:d:D:e:f:F:hi:IlLm:MnN:p:P:r:R:Ss:tT:vVXzZ");
			if( cmd == -1 )
				break;

			switch( cmd )
			{
			case 'a':	// Clear Database
				clear_database = true;
				clearDbNames.push_back(string(optarg));
				break;

			case 'b':	// Barry backup filename (tar.gz)
#ifdef __BARRY_BACKUP_MODE__
				if( filename.size() == 0 ) {
					filename = optarg;
					bbackup_mode = true;
				}
				else {
					cerr << "Do not use -f with -b\n";
					return 1;
				}
#else
				cerr << "-b option not supported - no Barry "
					"Backup library support available\n";
				return 1;
#endif
				break;

			case 'B':	// busname
				busname = optarg;
				break;

			case 'c':	// contacts to ldap ldif
				ldif_contacts = true;
				ldifBaseDN = optarg;
				break;

			case 'C':	// DN Attribute for FQDN
				ldifDnAttr = optarg;
				break;

			case 'd':	// show dbname
				dbNames.push_back(string(optarg));
				break;

			case 'D':	// delete record
				stCommands.push_back(
					StateTableCommand('D', false, atoi(optarg)));
				break;

			case 'e':	// endpoint override
				if( !ParseEpOverride(optarg, &epOverride) ) {
					Usage();
					return 1;
				}
				epp_override = true;
				break;

			case 'f':	// filename
#ifdef __BTOOL_BOOST_MODE__
				if( !bbackup_mode && filename.size() == 0 ) {
					filename = optarg;
				}
				else {
					cerr << "Do not use -f with -b\n";
					return 1;
				}
#else
				cerr << "-f option not supported - no Boost "
					"serialization support available\n";
				return 1;
#endif
				break;

			case 'F':	// sort key
				ParseSortKey(optarg);
				break;

			case 'i':	// international charset (iconv)
				iconvCharset = optarg;
				break;

			case 'I':	// sort before dump
				sort_records = true;
				break;

			case 'l':	// list only
				list_only = true;
				break;

			case 'L':	// List Contact field names
				list_contact_fields = true;
				break;

			case 'm':	// Map / Unmap
				mapCommands.push_back(string(optarg));
				break;

			case 'M':	// List LDIF map
				list_ldif_map = true;
				break;

			case 'n':	// use null parser
				null_parser = true;
				break;

			case 'N':	// Devname
				devname = optarg;
				break;

			case 'p':	// Blackberry PIN
				pin = strtoul(optarg, NULL, 16);
				break;

			case 'P':	// Device password
				password = optarg;
				break;

			case 'r':	// get specific record index
				stCommands.push_back(
					StateTableCommand('r', false, atoi(optarg)));
				break;

			case 'R':	// same as 'r', and clears dirty
				stCommands.push_back(
					StateTableCommand('r', true, atoi(optarg)));
				break;

			case 's':	// save dbname
				saveDbNames.push_back(string(optarg));
				break;

			case 'S':	// show supported databases
				if( show_parsers )
					show_fields = true;
				else
					show_parsers = true;
				break;

			case 't':	// display database database
				show_dbdb = true;
				break;

			case 'T':	// show RecordStateTable
				record_state_table = true;
				dbNames.push_back(string(optarg));
				break;

			case 'v':	// data dump on
				data_dump = true;
				break;

			case 'V':	// vformat MIME mode
#ifdef __BARRY_SYNC_MODE__
				vformat_mode = true;
#else
				cerr << "-V option not supported - no Sync "
					"library support available\n";
				return 1;
#endif
				break;

			case 'X':	// reset device
				reset_device = true;
				break;

			case 'z':	// non-threaded sockets
				threaded_sockets = false;
				break;

			case 'Z':	// threaded socket router
				threaded_sockets = true;
				break;

			case 'h':	// help
			default:
				Usage();
				return 0;
			}
		}

		if( show_parsers ) {
			ShowParsers(show_fields, true);
			ShowBuilders();
			return 0;
		}

		// Initialize the barry library.  Must be called before
		// anything else.
		Barry::Init(data_dump);
		if( data_dump ) {
			int logical, major, minor;
			const char *Version = Barry::Version(logical, major, minor);
			cout << Version << endl;
		}

		// Create an IConverter object if needed
		auto_ptr<IConverter> ic;
		if( iconvCharset.size() ) {
			ic.reset( new IConverter(iconvCharset.c_str(), true) );
		}

		// LDIF class... only needed if ldif output turned on
		ContactLdif ldif(ldifBaseDN);
		DoMapping(ldif, mapCommands);
		if( ldifDnAttr.size() ) {
			if( !ldif.SetDNAttr(ldifDnAttr) ) {
				cerr << "Unable to set DN Attr: " << ldifDnAttr << endl;
			}
		}

		// Probe the USB bus for Blackberry devices and display.
		// If user has specified a PIN, search for it in the
		// available device list here as well
		Barry::Probe probe(busname.c_str(), devname.c_str(),
			epp_override ? &epOverride : 0);
		int activeDevice = -1;

		// show any errors during probe first
		if( probe.GetFailCount() ) {
			if( ldif_contacts )
				cout << "# ";
			cout << "Blackberry device errors with errors during probe:" << endl;
			for( int i = 0; i < probe.GetFailCount(); i++ ) {
				if( ldif_contacts )
					cout << "# ";
				cout << probe.GetFailMsg(i) << endl;
			}
		}

		// show all successfully found devices
		if( ldif_contacts )
			cout << "# ";
		cout << "Blackberry devices found:" << endl;
		for( int i = 0; i < probe.GetCount(); i++ ) {
			if( ldif_contacts )
				cout << "# ";
			if( data_dump )
				probe.Get(i).DumpAll(cout);
			else
				cout << probe.Get(i);
			cout << endl;
			if( probe.Get(i).m_pin == pin )
				activeDevice = i;
		}

		if( list_only )
			return 0;	// done

		if( activeDevice == -1 ) {
			if( pin == 0 ) {
				// can we default to single device?
				if( probe.GetCount() == 1 )
					activeDevice = 0;
				else {
					cerr << "No device selected" << endl;
					return 1;
				}
			}
			else {
				cerr << "PIN " << setbase(16) << pin
					<< " not found" << endl;
				return 1;
			}
		}

		if( ldif_contacts )
			cout << "# ";
		cout << "Using device (PIN): "
			<< probe.Get(activeDevice).m_pin.Str() << endl;

		if( reset_device ) {
			Usb::Device dev(probe.Get(activeDevice).m_dev);
			dev.Reset();
			return 0;
		}

		// Override device endpoints if user asks
		Barry::ProbeResult device = probe.Get(activeDevice);
		if( epp_override ) {
			device.m_ep.read = epOverride.read;
			device.m_ep.write = epOverride.write;
			// FIXME - override this too?
			device.m_ep.type = Usb::EndpointDescriptor::BulkType;
			cout << "Endpoint pair (read,write) overridden with: "
			     << hex
			     << (unsigned int) device.m_ep.read << ","
			     << (unsigned int) device.m_ep.write << endl;
		}

		//
		// execute each mode that was turned on
		//


		// Dump current LDIF mapping
		if( list_ldif_map ) {
			cout << ldif << endl;
		}

		// Dump list of Contact field names
		if( list_contact_fields ) {
			for( const ContactLdif::NameToFunc *n = ldif.GetFieldNames(); n->name; n++ ) {
				cout.fill(' ');
				cout << "  " << left << setw(20) << n->name << ": "
					<< n->description << endl;
			}
		}

		// Check if Desktop access is needed
		if( !(	show_dbdb ||
			ldif_contacts ||
			record_state_table ||
			clear_database ||
			stCommands.size() ||
			dbNames.size() ||
			saveDbNames.size() ) )
			return 0;	// done

		//
		// Create our controller object
		//
		// Order is important in the following auto_ptr<> objects,
		// since Controller must get destroyed before router.
		// Normally you'd pick one method, and not bother
		// with auto_ptr<> and so the normal C++ constructor
		// rules would guarantee this safety for you, but
		// here we want the user to pick.
		//
		auto_ptr<SocketRoutingQueue> router;
		if( threaded_sockets ) {
			router.reset( new SocketRoutingQueue );
			router->SpinoffSimpleReadThread();
		}

		DesktopConnector connector(password.c_str(),
			iconvCharset, device, router.get());
		if( !connector.Connect() ) {
			// bad password (default action is not to prompt)
			cerr << connector.GetBadPassword().what() << endl;
			return 1;
		}

		Barry::Mode::Desktop &desktop = connector.GetDesktop();

		// Dump list of all databases to stdout
		if( show_dbdb ) {
			// open desktop mode socket
			cout << desktop.GetDBDB() << endl;
		}

		// Dump list of contacts to an LDAP LDIF file
		// This uses the Controller convenience templates
		if( ldif_contacts ) {
			// create a storage functor object that accepts
			// Barry::Contact objects as input
			Contact2Ldif storage(ldif);

			// load all the Contact records into storage
			desktop.LoadDatabaseByType<Barry::Contact>(storage);
		}

		// Dump record state table to stdout
		if( record_state_table ) {
			if( dbNames.size() == 0 ) {
				cout << "No db names to process" << endl;
				return 1;
			}

			vector<string>::iterator b = dbNames.begin();
			for( ; b != dbNames.end(); b++ ) {
				unsigned int id = desktop.GetDBID(*b);
				RecordStateTable state;
				desktop.GetRecordStateTable(id, state);
				cout << "Record state table for: " << *b << endl;
				cout << state;
			}
			return 0;
		}

		// Get Record mode overrides the default name mode
		if( stCommands.size() ) {
			if( dbNames.size() != 1 ) {
				cout << "Must have 1 db name to process" << endl;
				return 1;
			}

			unsigned int id = desktop.GetDBID(dbNames[0]);
			shared_ptr<Parser> parse = GetParser(dbNames[0],filename,
				null_parser, true, vformat_mode, bbackup_mode);

			for( unsigned int i = 0; i < stCommands.size(); i++ ) {
				desktop.GetRecord(id, stCommands[i].index, *parse.get());

				if( stCommands[i].flag == 'r' && stCommands[i].clear ) {
					cout << "Clearing record's dirty flags..." << endl;
					desktop.ClearDirty(id, stCommands[i].index);
				}

				if( stCommands[i].flag == 'D' ) {
					desktop.DeleteRecord(id, stCommands[i].index);
				}
			}

			return 0;
		}

		// Dump contents of selected databases to stdout, or
		// to file if specified.
		// This is retrieving data from the Blackberry.
		if( dbNames.size() ) {
			vector<string>::iterator b = dbNames.begin();

			for( ; b != dbNames.end(); b++ ) {
				shared_ptr<Parser> parse = GetParser(*b,
					filename, null_parser, !sort_records,
					vformat_mode, bbackup_mode);
				unsigned int id = desktop.GetDBID(*b);
				desktop.LoadDatabase(id, *parse.get());
			}
		}

		// Clear databases
		if( clear_database ) {
			if( clearDbNames.size() == 0 ) {
				cout << "No db names to erase" << endl;
				return 1;
			}

			vector<string>::iterator b = clearDbNames.begin();

			for( ; b != clearDbNames.end(); b++ ) {
				unsigned int id = desktop.GetDBID(*b);
				cout << "Deleting all records from " << (*b) << "..." << endl;
				desktop.ClearDatabase(id);
			}

			return 0;
		}

		// Save contents of file to specified databases
		// This is writing data to the Blackberry.
		if( saveDbNames.size() ) {
			vector<string>::iterator b = saveDbNames.begin();

			for( ; b != saveDbNames.end(); b++ ) {
				shared_ptr<Builder> build = GetBuilder(*b,
					filename);
				unsigned int id = desktop.GetDBID(*b);
				desktop.SaveDatabase(id, *build);
			}
		}

	}
	catch( Usb::Error &ue ) {
		std::cerr << "Usb::Error caught: " << ue.what() << endl;
		return 1;
	}
	catch( Barry::Error &se ) {
		std::cerr << "Barry::Error caught: " << se.what() << endl;
		return 1;
	}
	catch( std::exception &e ) {
		std::cerr << "std::exception caught: " << e.what() << endl;
		return 1;
	}

	return 0;
}

