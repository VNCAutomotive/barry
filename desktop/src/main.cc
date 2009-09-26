///
/// \file	main.cc
///		Program entry point for the desktop gui
///

/*
    Copyright (C) 2009, Net Direct Inc. (http://www.netdirect.ca/)

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

#include <iostream>
#include <stdexcept>
#include <barry/barry.h>
#include "os22.h"
#include "os40.h"

using namespace std;

void Test(OpenSyncAPI &os)
{
	string_list_type list;

	cout << "=======================================================\n";
	cout << " Begin test run\n";
	cout << "=======================================================\n";

	cout << os.GetVersion() << endl;

	os.GetPluginNames(list);
	cout << "Plugins:\n" << list << endl;

	os.GetGroupNames(list);
	cout << "Groups:\n" << list << endl;
}

int main()
{
	Barry::Init(true);

	try {

		OpenSync40 os40;
		Test(os40);

		OpenSync22 os22;
		Test(os22);

	} catch(std::exception &e ) {
		cout << e.what() << endl;
		return 1;
	}

	return 0;
}
