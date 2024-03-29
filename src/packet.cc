///
/// \file	packet.cc
///		Low level protocol packet builder class.
///		Has knowledge of specific protocol commands in order
///		to hide protocol details behind an API.
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

#include "packet.h"
#include "m_desktop.h"
#include "protocol.h"
#include "protostructs.h"
#include "data.h"
#include "endian.h"
#include "parser.h"
#include "builder.h"
#include "error.h"
#include <string.h>

#define __DEBUG_MODE__
#include "debug.h"


namespace Barry {

//////////////////////////////////////////////////////////////////////////////
// Packet base class

//
// Command
//
/// Returns the command value of the receive packet.  If receive isn't
/// large enough, throws Error.
///
unsigned int Packet::Command() const
{
	Protocol::CheckSize(*m_receive, SB_PACKET_HEADER_SIZE);
	MAKE_PACKET(rpack, *m_receive);
	return rpack->command;
}


//////////////////////////////////////////////////////////////////////////////
// ZeroPacket class

ZeroPacket::ZeroPacket(Data &send, Data &receive)
	: Packet(send, receive)
{
}

ZeroPacket::~ZeroPacket()
{
}

//
// GetAttribute
//
/// Builds a command packet for the initial socket-0 handshakes
/// that fetch certain (some unknown) attributes.  The attributes
/// appear to exist in an object/attribute sequence, so that's
/// how we address them here.
///
void ZeroPacket::GetAttribute(unsigned int object, unsigned int attribute)
{
	size_t size = SB_SOCKET_PACKET_HEADER_SIZE + ATTRIBUTE_FETCH_COMMAND_SIZE;
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(size));
	Protocol::Packet &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(size);
	packet.command = SB_COMMAND_FETCH_ATTRIBUTE;
	packet.u.socket.socket = htobs(0x00ff);	// default non-socket request
	packet.u.socket.sequence = 0;		// filled in by Socket class
	packet.u.socket.u.fetch.object = htobs(object);
	packet.u.socket.u.fetch.attribute = htobs(attribute);

	m_send.ReleaseBuffer(size);
}

//
// Echo
//
/// Builds command packet for sending echo request.  The parameter
/// to this command is the number of microseconds elapsed since host
/// computer startup.
///
void ZeroPacket::Echo(uint64_t us_ticks)
{
	size_t size = SB_SOCKET_PACKET_HEADER_SIZE + ECHO_COMMAND_SIZE;
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(size));
	Protocol::Packet &packet = *cpack;

	packet.size = htobs(size);
	packet.command = SB_COMMAND_ECHO;
	packet.u.socket.socket = htobs(0x00ff);	// default non-socket request
	packet.u.socket.sequence = 0;		// filled in by Socket class
	packet.u.socket.u.echo.ticks = htobl(us_ticks);

	m_send.ReleaseBuffer(size);
}

void ZeroPacket::Reset()
{
	size_t size = SB_SOCKET_PACKET_HEADER_SIZE;
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(size));
	Protocol::Packet &packet = *cpack;

	packet.size = htobs(size);
	packet.command = SB_COMMAND_RESET;
	packet.u.socket.socket = htobs(0x00ff);	// default non-socket request
	packet.u.socket.sequence = 0;		// filled in by Socket class

	m_send.ReleaseBuffer(size);
}

unsigned int ZeroPacket::ObjectID() const
{
	Protocol::CheckSize(*m_receive, SB_SOCKET_PACKET_HEADER_SIZE);
	MAKE_PACKET(rpack, *m_receive);
	return btohs(rpack->u.socket.u.fetch.object);
}

unsigned int ZeroPacket::AttributeID() const
{
	Protocol::CheckSize(*m_receive, SB_SOCKET_PACKET_HEADER_SIZE);
	MAKE_PACKET(rpack, *m_receive);
	return btohs(rpack->u.socket.u.fetch.attribute);
}

uint32_t ZeroPacket::ChallengeSeed() const
{
	Protocol::CheckSize(*m_receive, SB_SOCKET_PACKET_HEADER_SIZE +
		PASSWORD_CHALLENGE_SEED_SIZE);
	MAKE_PACKET(rpack, *m_receive);
	return btohl(rpack->u.socket.u.password.u.seed);
}

unsigned int ZeroPacket::RemainingTries() const
{
	Protocol::CheckSize(*m_receive, SB_SOCKET_PACKET_HEADER_SIZE +
		PASSWORD_CHALLENGE_HEADER_SIZE);
	MAKE_PACKET(rpack, *m_receive);
	// this is a byte, so no byte swapping needed
	return rpack->u.socket.u.password.remaining_tries;
}

unsigned int ZeroPacket::SocketResponse() const
{
	Protocol::CheckSize(*m_receive, SB_SOCKET_PACKET_HEADER_SIZE);
	MAKE_PACKET(rpack, *m_receive);
	return btohs(rpack->u.socket.socket);
}

unsigned char ZeroPacket::SocketSequence() const
{
	Protocol::CheckSize(*m_receive, SB_SOCKET_PACKET_HEADER_SIZE);
	MAKE_PACKET(rpack, *m_receive);
	return rpack->u.socket.sequence;	// sequence is a byte
}

uint8_t ZeroPacket::CommandResponse() const
{
	Protocol::CheckSize(*m_receive, SB_SOCKET_PACKET_HEADER_SIZE);
	MAKE_PACKET(rpack, *m_receive);
	return rpack->command;
}



//////////////////////////////////////////////////////////////////////////////
// DBPacket class

DBPacket::DBPacket(Mode::Desktop &con, Data &send, Data &receive)
	: Packet(send, receive)
	, m_con(con)
	, m_last_dbop(0)
{
}

DBPacket::~DBPacket()
{
}

//
// ClearDatabase
//
/// Builds a command packet for the CLEAR_DATABASE command code, placing
/// the data in the send buffer.
///
void DBPacket::ClearDatabase(unsigned int dbId)
{
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(9));
	Protocol::Packet &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(9);
	packet.command = SB_COMMAND_DB_DATA;
	packet.u.db.tableCmd = m_con.GetDBCommand(Mode::Desktop::DatabaseAccess);
	packet.u.db.u.command.operation = SB_DBOP_CLEAR_DATABASE;
	packet.u.db.u.command.databaseId = htobs(dbId);

	m_send.ReleaseBuffer(9);

	m_last_dbop = SB_DBOP_CLEAR_DATABASE;
}

//
// GetDBDB
//
/// Builds a command packet for the GET_DBDB command code, placing the
/// data in m_send.
///
void DBPacket::GetDBDB()
{
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(7));
	Protocol::Packet &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(7);
	packet.command = SB_COMMAND_DB_DATA;
	packet.u.db.tableCmd = m_con.GetDBCommand(Mode::Desktop::DatabaseAccess);
//	packet.u.db.u.command.operation = SB_DBOP_GET_DBDB;
	packet.u.db.u.command.operation = SB_DBOP_OLD_GET_DBDB;

	m_send.ReleaseBuffer(7);

	m_last_dbop = SB_DBOP_OLD_GET_DBDB;
}

//
// GetRecordStateTable
//
/// Builds a command packet in the send buffer for the
/// GET_RECORD_STATE_TABLE command.
///
void DBPacket::GetRecordStateTable(unsigned int dbId)
{
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(9));
	Protocol::Packet &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(9);
	packet.command = SB_COMMAND_DB_DATA;
	packet.u.db.tableCmd = m_con.GetDBCommand(Mode::Desktop::DatabaseAccess);
	packet.u.db.u.command.operation = SB_DBOP_GET_RECORD_STATE_TABLE;
	packet.u.db.u.command.databaseId = htobs(dbId);

	m_send.ReleaseBuffer(9);

	m_last_dbop = SB_DBOP_GET_RECORD_STATE_TABLE;
}

//
// SetRecordFlags
//
/// Builds a command packet in the send buffer for the SET_RECORD_FLAGS
/// command code.
///
/// FIXME - this API call is incomplete, since there are unknown flags
///         in the SetRecordFlags protocol packet.  Currently it is only
///         used to set all flags to zero.
///
void DBPacket::SetRecordFlags(unsigned int dbId, unsigned int stateTableIndex,
			    uint8_t flag1)
{
	size_t size = SB_PACKET_COMMAND_HEADER_SIZE + DBC_RECORD_FLAGS_SIZE;
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(size));
	Protocol::Packet &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(size);
	packet.command = SB_COMMAND_DB_DATA;
	packet.u.db.tableCmd = m_con.GetDBCommand(Mode::Desktop::DatabaseAccess);
	packet.u.db.u.command.operation = SB_DBOP_SET_RECORD_FLAGS;
	packet.u.db.u.command.databaseId = htobs(dbId);
	packet.u.db.u.command.u.flags.unknown = flag1;
	packet.u.db.u.command.u.flags.index = htobs(stateTableIndex);
	memset(packet.u.db.u.command.u.flags.unknown2, 0, sizeof(packet.u.db.u.command.u.flags.unknown2));

	m_send.ReleaseBuffer(size);

	m_last_dbop = SB_DBOP_SET_RECORD_FLAGS;
}

//
// DeleteRecordByIndex
//
/// Builds a command packet in the send buffer for the DELETE_RECORD_BY_INDEX
/// command code.
///
void DBPacket::DeleteRecordByIndex(unsigned int dbId, unsigned int stateTableIndex)
{
	size_t size = SB_PACKET_COMMAND_HEADER_SIZE + DBC_RECORD_HEADER_SIZE;
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(size));
	Protocol::Packet &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(size);
	packet.command = SB_COMMAND_DB_DATA;
	packet.u.db.tableCmd = m_con.GetDBCommand(Mode::Desktop::DatabaseAccess);
	packet.u.db.u.command.operation = SB_DBOP_DELETE_RECORD_BY_INDEX;
	packet.u.db.u.command.databaseId = htobs(dbId);
	packet.u.db.u.command.u.record.recordIndex = htobs(stateTableIndex);

	m_send.ReleaseBuffer(size);

	m_last_dbop = SB_DBOP_DELETE_RECORD_BY_INDEX;
}

//
// GetRecordByIndex
//
/// Builds a command packet in the send buffer for the GET_RECORD_BY_INDEX
/// command code.
///
void DBPacket::GetRecordByIndex(unsigned int dbId, unsigned int stateTableIndex)
{
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(11));
	Protocol::Packet &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(11);
	packet.command = SB_COMMAND_DB_DATA;
	packet.u.db.tableCmd = m_con.GetDBCommand(Mode::Desktop::DatabaseAccess);
	packet.u.db.u.command.operation = SB_DBOP_GET_RECORD_BY_INDEX;
	packet.u.db.u.command.databaseId = htobs(dbId);
	packet.u.db.u.command.u.record.recordIndex = htobs(stateTableIndex);

	m_send.ReleaseBuffer(11);

	m_last_dbop = SB_DBOP_GET_RECORD_BY_INDEX;
}

//
// SetRecordByIndex
//
/// Builds a command packet in the m_send buffer for the SET_RECORD_BY_INDEX
/// command code.
///
/// \return	bool
///		- true means success
///		- false means no data available from Builder object
///
bool DBPacket::SetRecordByIndex(unsigned int dbId, unsigned int stateTableIndex,
			      Builder &build, const IConverter *ic)
{
	// build packet data
	DBData send(m_send, false);	// send is just a reference to m_send,
					// so it is safe to use m_send later

	size_t header_size = SB_PACKET_COMMAND_HEADER_SIZE + DBC_INDEXED_UPLOAD_HEADER_SIZE;
	if( !build.BuildRecord(send, header_size, ic) )
		return false;		// no data available
	size_t total_size = m_send.GetSize();

	// fill in the header values
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(total_size));
	Protocol::Packet &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(total_size);
	packet.command = SB_COMMAND_DB_DATA;
	packet.u.db.tableCmd = m_con.GetDBCommand(Mode::Desktop::DatabaseAccess);
	packet.u.db.u.command.operation = SB_DBOP_SET_RECORD_BY_INDEX;
	packet.u.db.u.command.databaseId = htobs(dbId);
	packet.u.db.u.command.u.index_upload.unknown = 0;
	packet.u.db.u.command.u.index_upload.index = htobs(stateTableIndex);

	m_send.ReleaseBuffer(total_size);

	m_last_dbop = SB_DBOP_SET_RECORD_BY_INDEX;
	return true;
}

//
// GetRecords
//
/// Builds a command packet in the send buffer for the GET_RECORDS
/// command code.
///
void DBPacket::GetRecords(unsigned int dbId)
{
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(9));
	Protocol::Packet &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(9);
	packet.command = SB_COMMAND_DB_DATA;
	packet.u.db.tableCmd = m_con.GetDBCommand(Mode::Desktop::DatabaseAccess);
	packet.u.db.u.command.operation = SB_DBOP_OLD_GET_RECORDS;
	packet.u.db.u.command.databaseId = htobs(dbId);

	m_send.ReleaseBuffer(9);

	m_last_dbop = SB_DBOP_OLD_GET_RECORDS;
}

//
// AddRecord
//
/// Builds a command packet in the m_send buffer for the ADD_RECORD command
/// code.
///
/// \return	bool
///		- true means success
///		- false means no data available from Builder object
///
bool DBPacket::AddRecord(unsigned int dbId, Builder &build, const IConverter *ic)
{
	// build packet data
	DBData send(m_send, false);	// send is just a reference to m_send,
					// so it is safe to use m_send later

	size_t header_size = SB_PACKET_COMMAND_HEADER_SIZE + DBC_TAGGED_UPLOAD_HEADER_SIZE;
	if( !build.BuildRecord(send, header_size, ic) )
		return false;		// no data available
	size_t total_size = m_send.GetSize();

	// fill in the header values
	MAKE_PACKETPTR_BUF(cpack, m_send.GetBuffer(total_size));
	Protocol::Packet &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(total_size);
	packet.command = SB_COMMAND_DB_DATA;
	packet.u.db.tableCmd = m_con.GetDBCommand(Mode::Desktop::DatabaseAccess);
	packet.u.db.u.command.operation = SB_DBOP_ADD_RECORD;
	packet.u.db.u.command.databaseId = htobs(dbId);
	packet.u.db.u.command.u.tag_upload.rectype = send.GetRecType();
	packet.u.db.u.command.u.tag_upload.uniqueId = htobl(send.GetUniqueId());
	packet.u.db.u.command.u.tag_upload.unknown2 = 1;	// unknown observed value

	m_send.ReleaseBuffer(total_size);

	m_last_dbop = SB_DBOP_ADD_RECORD;
	return true;
}


// throws FIXME if packet doesn't support it
unsigned int DBPacket::ReturnCode() const
{
	if( Command() == SB_COMMAND_DB_DONE ) {
		Protocol::CheckSize(*m_receive, SB_PACKET_DBACCESS_HEADER_SIZE + SB_DBACCESS_RETURN_CODE_SIZE);
		MAKE_PACKET(rpack, *m_receive);
		return rpack->u.db.u.return_code;
	}
	else {
		throw Error("Attempting to extract a return code from the wrong response packet type");
	}
}

//
// DBOperation
//
/// Returns the database operation code from the receive packet, assuming
/// that receive contains a response packet.  If receive isn't large
/// enough, throws Error.
///
unsigned int DBPacket::DBOperation() const
{
	Protocol::CheckSize(*m_receive, SB_PACKET_RESPONSE_HEADER_SIZE);
	MAKE_PACKET(rpack, *m_receive);
	return rpack->u.db.u.response.operation;
}

//
// Parse
//
/// Parses the data in the receive buffer, and attempts to be smart about it,
/// using the last send command as guidance for what to expect in the
/// response.
///
/// \returns	bool	true - packet was recognized and parse was attempted
///			false - packet was not recognized
///
bool DBPacket::Parse(Parser &parser, const std::string &dbname,
			const IConverter *ic)
{
	size_t offset = 0;
	MAKE_PACKET(rpack, *m_receive);

	switch( m_last_dbop )
	{
	case SB_DBOP_OLD_GET_RECORDS:
	case SB_DBOP_GET_RECORD_BY_INDEX:
		offset = SB_PACKET_RESPONSE_HEADER_SIZE + DBR_OLD_TAGGED_RECORD_HEADER_SIZE;
		Protocol::CheckSize(*m_receive, offset);

		// FIXME - this may need adjustment for email records... they
		// don't seem to have uniqueID's
		{
			DBData block(DBData::REC_VERSION_1, dbname,
				rpack->u.db.u.response.u.tagged.rectype,
				btohl(rpack->u.db.u.response.u.tagged.uniqueId),
				offset, *m_receive, false);
			parser.ParseRecord(block, ic);
		}
		return true;

	default:	// unknown command
		return false;
	}
}

//
// ParseMeta
//
/// Fills DBData's meta data based on its data block, and the last dbop.
///
bool DBPacket::ParseMeta(DBData &data)
{
	size_t offset = 0;
	MAKE_PACKET(rpack, data.GetData());

	switch( m_last_dbop )
	{
	case SB_DBOP_OLD_GET_RECORDS:
	case SB_DBOP_GET_RECORD_BY_INDEX:
		data.SetVersion(DBData::REC_VERSION_1);

		offset = SB_PACKET_RESPONSE_HEADER_SIZE + DBR_OLD_TAGGED_RECORD_HEADER_SIZE;
		Protocol::CheckSize(data.GetData(), offset);
		data.SetOffset(offset);

		// FIXME - this may need adjustment for email records... they
		// don't seem to have uniqueID's
		data.SetIds(rpack->u.db.u.response.u.tagged.rectype,
			btohl(rpack->u.db.u.response.u.tagged.uniqueId));
		return true;

	default:	// unknown command
		return false;
	}
}



//////////////////////////////////////////////////////////////////////////////
// JLPacket class

JLPacket::JLPacket(Data &cmd, Data &send, Data &receive)
	: Packet(send, receive)
	, m_cmd(cmd)
	, m_data(send)
	, m_last_set_size(0)
{
}

JLPacket::~JLPacket()
{
}

unsigned int JLPacket::Size()
{
	Protocol::CheckSize(*m_receive, SB_JLPACKET_HEADER_SIZE + SB_JLRESPONSE_HEADER_SIZE);
	MAKE_JLPACKET(rpack, *m_receive);
	return btohs(rpack->u.response.expect);
}


// returns 1 or 2 depending on whether cmd or cmd+send are available
int JLPacket::SimpleCmd(uint8_t cmd, uint8_t unknown, uint16_t size)
{
	MAKE_JLPACKETPTR_BUF(cpack, m_cmd.GetBuffer(8));
	Protocol::JLPacket &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(8);
	packet.u.command.command = cmd;
	packet.u.command.unknown = unknown;
	packet.u.command.size = htobs(size);

	m_cmd.ReleaseBuffer(8);

	return m_last_set_size = 1;
}

int JLPacket::SimpleData(const void *data, uint16_t size)
{
	uint16_t total = size + 4;

	MAKE_JLPACKETPTR_BUF(dpack, m_data.GetBuffer(total));

	// socket class sets socket for us
	dpack->size = htobs(total);
	memcpy(dpack->u.raw, data, size);

	m_data.ReleaseBuffer(total);

	return m_last_set_size = 2;
}

int JLPacket::BigEndianData(uint16_t value)
{
	value = be_htobs(value);
	return SimpleData(&value, sizeof(value));
}

int JLPacket::BigEndianData(uint32_t value)
{
	value = be_htobl(value);
	return SimpleData(&value, sizeof(value));
}

int JLPacket::SetUnknown1()
{
	SimpleCmd(SB_COMMAND_JL_SET_UNKNOWN1, 0, 1);
	uint8_t arg = 0;
	return SimpleData(&arg, 1);
}

int JLPacket::SetCodFilename(const std::string &filename)
{
	SimpleCmd(SB_COMMAND_JL_SET_COD_FILENAME, 0, filename.size());
	return SimpleData(filename.data(), filename.size());
}

int JLPacket::SetCodSize(off_t size)
{
	SimpleCmd(SB_COMMAND_JL_SET_COD_SIZE, 1, 4);
	return BigEndianData((uint32_t)size);
}

int JLPacket::SetTime(time_t when)
{
	SimpleCmd(SB_COMMAND_JL_SET_TIME, 0, 4);
	return BigEndianData((uint32_t)when);
}

int JLPacket::GetSubDir(uint16_t id)
{
	SimpleCmd(SB_COMMAND_JL_GET_SUBDIR, 0, 2);
	return BigEndianData(id);
}

int JLPacket::GetDirEntry(uint8_t entry_cmd, uint16_t id)
{
	SimpleCmd(entry_cmd, 0, 2);
	return BigEndianData(id);
}

int JLPacket::GetScreenshot()
{
	SimpleCmd(SB_COMMAND_JL_GET_SCREENSHOT, 0, 4);
	return BigEndianData((uint32_t) 0);
}

int JLPacket::Erase(uint16_t cmd, uint16_t id)
{
	SimpleCmd((uint8_t)cmd, 0, 2);
	return BigEndianData(id);
}

int JLPacket::GetEventlogEntry(uint16_t entry_num)
{
	SimpleCmd(SB_COMMAND_JL_GET_LOG_ENTRY, 0, 2);
	return BigEndianData(entry_num);
}

int JLPacket::SaveModule(uint16_t id)
{
	SimpleCmd(SB_COMMAND_JL_SAVE_MODULE, 0, 2);
	return BigEndianData(id);
}

int JLPacket::PutData(const void *data, uint16_t size)
{
	SimpleCmd(SB_COMMAND_JL_SEND_DATA, 0, size);
	return SimpleData(data, size);
}


//////////////////////////////////////////////////////////////////////////////
// JVMPacket class

JVMPacket::JVMPacket(Data &send, Data &receive)
	: Packet(send, receive)
	, m_cmd(send)
{
}

JVMPacket::~JVMPacket()
{
}


unsigned int JVMPacket::Size()
{
	MAKE_JVMPACKET(rpack, *m_receive);
	Protocol::CheckSize(*m_receive, SB_JVMPACKET_HEADER_SIZE + sizeof(rpack->u.expect));
	return be_btohs(rpack->u.expect);
}


// Command format (param is optionnal) :
// 00000000: 05 00 07 00 00 01 8a
//                             ^^ : command
//                       ^^^^^ : size of commd + param
//                 ^^^^^ : packet size
//           ^^^^^ : socket ID
void JVMPacket::SimpleCmd(uint8_t cmd)
{
	// 4 : socket id field + packet size field
	// 2 : size field
	// 1 : command field
	const uint16_t total = 4 + 2 + 1;

	MAKE_JVMPACKETPTR_BUF(cpack, m_cmd.GetBuffer(total));
	Protocol::JVMPacket &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(total);
	packet.u.command.size = be_htobs(1);
	packet.u.command.command = cmd;

	m_cmd.ReleaseBuffer(total);
}

// Command with parameter format :
// 00000000: 05 00 0b 00 00 05 8d 00 00 00 00
//                                ^^^^^^^^^^^ : param
//                             ^^ : command
//                       ^^^^^ : size of commd + param
//                 ^^^^^ : packet size
//           ^^^^^ : socket ID
void JVMPacket::ComplexCmd(uint8_t cmd, const void *param, uint16_t size)
{
	// 4 : socket id field + packet size field
	// 2 : size field
	// 1 : command field
	uint16_t total = 4 + 2 + 1 + size;

	MAKE_JVMPACKETPTR_BUF(cpack, m_cmd.GetBuffer(total));
	Protocol::JVMPacket &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(total);
	packet.u.command.size = be_htobs(1 + size);
	packet.u.command.command = cmd;

	if ((size > 0) && (param != NULL))
		memcpy(cpack->u.command.raw, param, size);

	m_cmd.ReleaseBuffer(total);
}


void JVMPacket::Unknown01() {
	SimpleCmd(SB_COMMAND_JVM_UNKNOWN01);
}


void JVMPacket::Unknown02() {
	SimpleCmd(SB_COMMAND_JVM_UNKNOWN02);
}


void JVMPacket::Unknown03() {
	SimpleCmd(SB_COMMAND_JVM_UNKNOWN03);
}


void JVMPacket::Unknown04() {
	SimpleCmd(SB_COMMAND_JVM_UNKNOWN04);
}


void JVMPacket::Unknown05() {
	SimpleCmd(SB_COMMAND_JVM_UNKNOWN05);
}


void JVMPacket::Unknown06() {
	uint32_t param = 0;

	ComplexCmd(SB_COMMAND_JVM_UNKNOWN06, &param, sizeof(param));
}


void JVMPacket::Unknown07() {
	uint32_t param = 0;

	ComplexCmd(SB_COMMAND_JVM_UNKNOWN07, &param, sizeof(param));
}


void JVMPacket::Unknown08() {
	uint32_t param = 0;

	ComplexCmd(SB_COMMAND_JVM_UNKNOWN08, &param, sizeof(param));
}


void JVMPacket::Unknown09() {
	uint32_t param = be_htobl(0x09);

	ComplexCmd(SB_COMMAND_JVM_UNKNOWN09, &param, sizeof(param));
}


void JVMPacket::Unknown10() {
	uint32_t param = be_htobl(0x01);

	ComplexCmd(SB_COMMAND_JVM_UNKNOWN10, &param, sizeof(param));
}


void JVMPacket::Unknown11(uint32_t id) {
	id = be_htobl(id);

	ComplexCmd(SB_COMMAND_JVM_UNKNOWN11, &id, sizeof(id));
}


void JVMPacket::Unknown12(uint32_t id) {
	id = be_htobl(id);

	ComplexCmd(SB_COMMAND_JVM_UNKNOWN12, &id, sizeof(id));
}


void JVMPacket::Unknown13(uint32_t id) {
	id = be_htobl(id);

	ComplexCmd(SB_COMMAND_JVM_UNKNOWN13, &id, sizeof(id));
}


void JVMPacket::Unknown14(uint32_t id) {
	id = be_htobl(id);

	ComplexCmd(SB_COMMAND_JVM_UNKNOWN14, &id, sizeof(id));
}


void JVMPacket::Unknown15(uint32_t id) {
	id = be_htobl(id);

	ComplexCmd(SB_COMMAND_JVM_UNKNOWN15, &id, sizeof(id));
}


void JVMPacket::GetModulesList(uint32_t id) {
	id = be_htobl(id);

	ComplexCmd(SB_COMMAND_JVM_GET_MODULES_LIST, &id, sizeof(id));
}


void JVMPacket::GetThreadsList() {
	SimpleCmd(SB_COMMAND_JVM_GET_THREADS_LIST);
}


void JVMPacket::GetConsoleMessage() {
	SimpleCmd(SB_COMMAND_JVM_GET_CONSOLE_MSG);
}


void JVMPacket::Go()
{
	SimpleCmd(SB_COMMAND_JVM_GO);
}


void JVMPacket::Stop()
{
	// 4 : socket id field + packet size field
	// 2 : value field
	const uint16_t total = 4 + 2;

	MAKE_JVMPACKETPTR_BUF(cpack, m_cmd.GetBuffer(total));
	Protocol::JVMPacket &packet = *cpack;

	// socket class sets socket for us
	packet.size = htobs(total);
	packet.u.value = be_htobs(SB_COMMAND_JVM_STOP);

	m_cmd.ReleaseBuffer(total);
}


void JVMPacket::GetStatus()
{
	SimpleCmd(SB_COMMAND_JVM_GET_STATUS);
}

} // namespace Barry

