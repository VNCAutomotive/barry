///
/// \file	parser.h
///		Virtual parser wrapper
///

/*
    Copyright (C) 2005-2006, Net Direct Inc. (http://www.netdirect.ca/)

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

#ifndef __BARRY_PARSER_H__
#define __BARRY_PARSER_H__

#include "data.h"
#include "protocol.h"
#include "debug.h"
#include <stdint.h>		// for uint32_t

namespace Barry {

// also acts as a null parser
//
// Parser class
//
/// Base class for the parser hierarchy.  If in debug mode, this
/// class can be used as a null parser.  Call Init() and the protocol
/// will be dumped to stdout and no parsing will be done.
///
class Parser
{
public:
	Parser() {}
	virtual ~Parser() {}

	virtual void Clear() {}
	virtual void SetUniqueId(uint32_t Id) {}
	virtual void ParseHeader(const Data &data, size_t &offset) {}
	virtual void ParseFields(const Data &data, size_t &offset) {}
	virtual void Store() {}
};


//
// RecordParser template class
//
/// Template class for easy creation of specific parser objects.  This template
/// takes the following template arguments:
///
///	- Record: One of the record parser classes in record.h
///	- Storage: A custom storage functor class.  An object of this type
///		will be called as a function with parsed Record as an
///		argument.  This happens on the fly as the data is retrieved
///		from the device over USB, so it should not block forever.
///
/// Example LoadDatabase() call:
///
/// <pre>
/// struct StoreContact
/// {
///     std::vector<Contact> &amp;array;
///     StoreContact(std::vector<Contact> &amp;a) : array(a) {}
///     void operator() (const Contact &amp;c)
///     {
///         array.push_back(c);
///     }
/// };
///
/// Controller con(probeResult);
/// con.OpenMode(Controller::Desktop);
/// std::vector<Contact> contactList;
/// StoreContact storage(contactList);
/// RecordParser<Contact, StoreContact> parser(storage);
/// con.LoadDatabase(con.GetDBID("Address Book"), parser);
/// </pre>
///
template <class Record, class Storage>
class RecordParser : public Parser
{
	Storage *m_store;
	bool m_owned;
	Record m_rec;

public:
	/// Constructor that references an externally managed storage object.
	RecordParser(Storage &storage)
		: m_store(&storage), m_owned(false) {}

	/// Constructor that references a locally managed storage object.
	/// The pointer passed in will be stored, and freed when this class
	/// is destroyed.  It is safe to call this constructor with
	/// a 'new'ly created storage object.
	RecordParser(Storage *storage)
		: m_store(storage), m_owned(true) {}

	~RecordParser()
	{
		if( this->m_owned )
			delete m_store;
	}

	virtual void Clear()
	{
		m_rec = Record();
	}

	virtual void SetUniqueId(uint32_t Id)
	{
		m_rec.SetUniqueId(Id);
	}

	virtual void ParseHeader(const Data &data, size_t &offset)
	{
		m_rec.ParseHeader(data, offset);
	}

	virtual void ParseFields(const Data &data, size_t &offset)
	{
		m_rec.ParseFields(data, offset);
	}

	virtual void Store()
	{
		(*m_store)(m_rec);
	}
};

} // namespace Barry

#endif

