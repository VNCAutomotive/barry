///
/// \file	BackupWindow.cc
///		GUI window class
///

/*
    Copyright (C) 2007-2008, Net Direct Inc. (http://www.netdirect.ca/)

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

#include "BackupWindow.h"
#include "DeviceSelectDlg.h"
#include "PasswordDlg.h"
#include "PromptDlg.h"
#include "ConfigDlg.h"
#include "util.h"
#include <gtkmm/aboutdialog.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>

BackupWindow::BackupWindow(BaseObjectType *cobject,
			   const Glib::RefPtr<Gnome::Glade::Xml> &xml)
	: Gtk::Window(cobject)
	, m_xml(xml)
	, m_recordTotal(0)
	, m_finishedRecords(0)
	, m_pProgressBar(0)
	, m_pStatusBar(0)
	, m_pBackupButton(0)
	, m_pRestoreButton(0)
	, m_pDeviceNameLabel(0)
	, m_scanned(false)
	, m_working(false)
{
	// setup menu signals
	Gtk::MenuItem *pItem = 0;
	m_xml->get_widget("menu_file_quit", pItem);
	pItem->signal_activate().connect(
		sigc::mem_fun(*this, &BackupWindow::on_file_quit));

	m_xml->get_widget("menu_edit_config", pItem);
	pItem->signal_activate().connect(
		sigc::mem_fun(*this, &BackupWindow::on_edit_config));

	m_xml->get_widget("menu_help_about", pItem);
	pItem->signal_activate().connect(
		sigc::mem_fun(*this, &BackupWindow::on_help_about));

	// get various widget pointers we will use later
	m_xml->get_widget("BackupButton", m_pBackupButton);
	m_xml->get_widget("RestoreButton", m_pRestoreButton);
	m_xml->get_widget("progressbar1", m_pProgressBar);
	m_xml->get_widget("statusbar1", m_pStatusBar);
	m_xml->get_widget("entry1", m_pPINEntry);
	m_xml->get_widget("entry2", m_pDatabaseEntry);
	m_xml->get_widget("DeviceNameLabel", m_pDeviceNameLabel);

	// setup widget signals
	m_pBackupButton->signal_clicked().connect(
		sigc::mem_fun(*this, &BackupWindow::on_backup));
	m_pRestoreButton->signal_clicked().connect(
		sigc::mem_fun(*this, &BackupWindow::on_restore));

	// setup thread dispatcher signals
	m_signal_progress.connect(
		sigc::mem_fun(*this, &BackupWindow::on_thread_progress));
	m_signal_error.connect(
		sigc::mem_fun(*this, &BackupWindow::on_thread_error));
	m_signal_done.connect(
		sigc::mem_fun(*this, &BackupWindow::on_thread_done));
	m_signal_erase_db.connect(
		sigc::mem_fun(*this, &BackupWindow::on_thread_erase_db));

	// setup startup device scan
	Glib::signal_timeout().connect(
		sigc::mem_fun(*this, &BackupWindow::on_startup), 500);

	m_pStatusBar->push("Ready");
	m_pProgressBar->set_fraction(0.00);

	// do this last so that any exceptions in the constructor
	// won't cause a connected signal handler to a non-object
	// (i.e. ~BackupWindow() won't get called if constructor throws)
	m_signal_handler_connection = Glib::add_exception_handler(
		sigc::mem_fun(*this, &BackupWindow::signal_exception_handler) );
}

BackupWindow::~BackupWindow()
{
	// disconnect the signal, as we're going out of business
	m_signal_handler_connection.disconnect();
}

void BackupWindow::ScanAndConnect()
{
	m_pStatusBar->push("Scanning for devices...");
	m_pStatusBar->show_now();

	int tries = 0;

sac_retry:
	tries++;
	Barry::Probe probe;
	uint32_t pin = 0;
	int nSelection = -1;

	if( probe.GetCount() > 1 ) {
		DeviceSelectDlg dlg(probe);
		if( dlg.run() == Gtk::RESPONSE_OK ) {
			pin = dlg.GetPIN();
			nSelection = probe.FindActive(pin);
		}
		else {
			// no selection, exit
			hide();
			return;
		}
	}
	else if( probe.GetCount() == 1 ) {
		// default to first
		pin = probe.Get(0).m_pin;
		nSelection = 0;
	}
	else {
		Gtk::MessageDialog msg("No BlackBerry devices found.");
		msg.run();
		hide();
		return;
	}

	if( nSelection == -1 ) {
		Gtk::MessageDialog msg("Internal error: unable to find pin.");
		msg.run();
		hide();
		return;
	}

	bool out_of_tries = false, password_required = false;
	int remaining_tries = 0;
	try {
		if( !m_dev.Connect(probe.Get(nSelection)) ) {
			Gtk::MessageDialog msg(m_dev.get_last_error());
			msg.run();
			hide();
			return;
		}
	}
	catch( Barry::BadPassword &bp ) {
		out_of_tries = bp.out_of_tries();
		remaining_tries = bp.remaining_tries();
		password_required = true;
	}
	catch( Barry::BadSize &bs ) {
		std::cerr << "Barry::BadSize caught in ScanAndConnect: "
			<< bs.what() << std::endl;
		if( tries < 2 ) {
			// BadSize during connect at startup usually means
			// the device didn't shutdown properly, so try
			// a reset or two before we give up
			Usb::Device dev(probe.Get(nSelection).m_dev);
			dev.Reset();
			sleep(2);
			goto sac_retry;
		}
		else {
			Gtk::MessageDialog msg(bs.what());
			msg.run();
			hide();
			return;
		}
	}

	if( password_required ) {
		// try password repeatedly until out of tries or
		// the user cancels... or success :-)

		bool connected = false;
		while( !connected && !out_of_tries ) try {
			PasswordDlg dlg(remaining_tries);
			if( dlg.run() == Gtk::RESPONSE_OK ) {
				connected = m_dev.Password(dlg.GetPassword());
				if( !connected ) {
					Gtk::MessageDialog msg(m_dev.get_last_error());
					msg.run();
					hide();
					return;
				}
			}
			else {
				// user cancelled
				hide();
				return;
			}
		}
		catch( Barry::BadPassword &bp ) {
			out_of_tries = bp.out_of_tries();
			remaining_tries = bp.remaining_tries();
			if( out_of_tries ) {
				Gtk::MessageDialog msg(bp.what());
				msg.run();
				hide();
				return;
			}
		}

		if( !connected ) {
			hide();
			return;
		}
	}

	std::ostringstream oss;
	oss << std::hex << pin;
	m_pPINEntry->set_text(oss.str());

	// open configuration now that we know which device we're talking to
	m_pConfig.reset( new ConfigFile(oss.str(), m_dev.GetDBDB()) );
	CheckDeviceName();
	SetDeviceName(m_pConfig->GetDeviceName());

	m_pStatusBar->pop();
}

void BackupWindow::CheckDeviceName()
{
	if( !m_pConfig->HasDeviceName() ) {
		PromptDlg dlg;
		dlg.SetPrompt("Unnamed device found. Please enter a name for it:");
		if( dlg.run() == Gtk::RESPONSE_OK ) {
			m_pConfig->SetDeviceName(dlg.GetAnswer());
		}
		else {
			m_pConfig->SetDeviceName(" ");
		}
		if( !m_pConfig->Save() ) {
			Gtk::MessageDialog msg("Error saving config: " +
				m_pConfig->get_last_error());
			msg.run();
		}
	}
}

void BackupWindow::SetDeviceName(const std::string &name)
{
	// format the device name prompt
	std::ostringstream dn;
	dn << "Device: <i>" << m_pConfig->GetDeviceName() << "</i>";
	m_pDeviceNameLabel->set_label(dn.str());

}

void BackupWindow::SetWorkingMode(const std::string &taskname)
{
	m_working = true;
	m_thread_error = false;
	m_pBackupButton->set_sensitive(false);
	m_pRestoreButton->set_sensitive(false);
	m_pStatusBar->push(taskname + " in progress...");
	m_pProgressBar->set_fraction(0.00);
}

void BackupWindow::ClearWorkingMode()
{
	m_working = false;
	m_pBackupButton->set_sensitive(true);
	m_pRestoreButton->set_sensitive(true);
	m_pStatusBar->pop();
	if( m_finishedRecords >= m_recordTotal ) {
		// only reset the progress bar on success
		m_pProgressBar->set_fraction(0.00);
	}

	std::ostringstream oss;
	oss << m_finishedRecords << " total records processed.";
	m_pDatabaseEntry->set_text(oss.str());
}

void BackupWindow::UpdateProgress()
{
	double done = (double)m_finishedRecords / m_recordTotal;
	// never say 100% unless really done
	if( done >= 1.0 && m_finishedRecords < m_recordTotal ) {
		done = 0.99;
	}
	m_pProgressBar->set_fraction(done);

	m_pDatabaseEntry->set_text(m_dev.GetThreadDBName());
}



void BackupWindow::signal_exception_handler()
{
	try {
		throw;
	}
	catch( Glib::Exception &e ) {
		// This usually just means a missing .glade file,
		// so we try to carry on.
		std::cerr << "Glib::Exception caught in main: " << std::endl;
		std::cerr << e.what() << std::endl;
		Gtk::MessageDialog msg(e.what());
		msg.run();
	}
	catch( ... ) {
		// anything else, terminate window and pass on to next handler
		// (which should be in main.cc)
		hide();
		throw;
	}
}


//////////////////////////////////////////////////////////////////////////////
// signal handlers

void BackupWindow::on_backup()
{
	// already working?
	if( m_working ) {
		Gtk::MessageDialog msg("Thread already in progress.");
		msg.run();
		return;
	}

	// make sure our target directory exists
	if( !::CheckPath(m_pConfig->GetPath()) ) {
		Gtk::MessageDialog msg("Could not create directory: " + m_pConfig->GetPath());
		msg.run();
		return;
	}

	// anything to do?
	if( m_pConfig->GetBackupList().size() == 0 ) {
		Gtk::MessageDialog msg("No databases selected in configuration.");
		msg.run();
		return;
	}

	// prepare for the progress bar
	m_recordTotal = m_dev.GetDeviceRecordTotal(m_pConfig->GetBackupList());
	m_finishedRecords = 0;
	m_modeName = "Backup";

	// anything to do?
	if( m_recordTotal == 0 ) {
		Gtk::MessageDialog msg("There are no records available in the selected databases.");
		msg.run();
		return;
	}

	// prompt for a backup label, if so configured
	std::string backupLabel;
	if( m_pConfig->PromptBackupLabel() ) {
		PromptDlg dlg;
		dlg.SetPrompt("Please enter a label for this backup:");
		if( dlg.run() == Gtk::RESPONSE_OK ) {
			backupLabel = dlg.GetAnswer();
		}
	}

	// start the thread
	m_working = m_dev.StartBackup(
		DeviceInterface::AppComm(&m_signal_progress,
					&m_signal_error,
					&m_signal_done,
					&m_signal_erase_db),
		m_pConfig->GetBackupList(), m_pConfig->GetPath(),
		m_pConfig->GetPIN(), backupLabel);
	if( !m_working ) {
		Gtk::MessageDialog msg("Error starting backup thread: " +
			m_dev.get_last_error());
		msg.run();
	}

	// update the GUI
	SetWorkingMode("Backup");
}

bool BackupWindow::PromptForRestoreTarball(std::string &restoreFilename,
					   const std::string &start_path)
{
	char buffer[PATH_MAX];
	char *buf = getcwd(buffer, PATH_MAX);

	// start at the base path given... if it fails, just open
	// the dialog where we are
	chdir(start_path.c_str());

	Gtk::FileChooserDialog dlg(*this, "Select backup to restore from");
	dlg.add_button(Gtk::Stock::OK, Gtk::RESPONSE_OK);
	dlg.add_button(Gtk::Stock::CANCEL, Gtk::RESPONSE_CANCEL);
	int result = dlg.run();

	if( buf )
		chdir(buf);

	if( result != Gtk::RESPONSE_OK )
		return false;

	restoreFilename = dlg.get_filename();
	return true;
}

void BackupWindow::on_restore()
{
	// already working?
	if( m_working ) {
		Gtk::MessageDialog msg("Thread already in progress.");
		msg.run();
		return;
	}

	std::string restoreFilename;
	if( !PromptForRestoreTarball(restoreFilename, m_pConfig->GetPath()) )
		return;	// nothing to do

	// prepare for the progress bar
	m_finishedRecords = 0;
	m_modeName = "Restore";

	// start the thread
	m_working = m_dev.StartRestore(
		DeviceInterface::AppComm(&m_signal_progress,
					&m_signal_error,
					&m_signal_done,
					&m_signal_erase_db),
		m_pConfig->GetRestoreList(), restoreFilename, &m_recordTotal);
//	m_working = m_dev.StartRestoreAndBackup(
//		DeviceInterface::AppComm(&m_signal_progress,
//					&m_signal_error,
//					&m_signal_done,
//					&m_signal_erase_db),
//		m_pConfig->GetRestoreList(), restoreFilename,
//		m_pConfig->GetPath(), m_pConfig->GetPIN(),
//		&m_recordTotal);
	if( !m_working ) {
		Gtk::MessageDialog msg("Error starting restore thread: " +
			m_dev.get_last_error());
		msg.run();
	}

std::cerr << "m_recordTotal for restore: " << m_recordTotal << std::endl;

	// update the GUI
	SetWorkingMode("Restore");
}

void BackupWindow::on_file_quit()
{
	m_dev.Disconnect();
	hide();
}

void BackupWindow::on_edit_config()
{
	ConfigDlg dlg(m_dev.GetDBDB(), *m_pConfig);
	if( dlg.run() == Gtk::RESPONSE_OK ) {
		m_pConfig->SetBackupList(dlg.GetBackupList());
		m_pConfig->SetRestoreList(dlg.GetRestoreList());
		m_pConfig->SetDeviceName(dlg.GetDeviceName());
		m_pConfig->SetPromptBackupLabel(dlg.GetPromptBackupLabel());
		if( !m_pConfig->Save() ) {
			Gtk::MessageDialog msg("Error saving config: " +
				m_pConfig->get_last_error());
			msg.run();
		}
		SetDeviceName(m_pConfig->GetDeviceName());
	}
}

void BackupWindow::on_help_about()
{
	Gtk::AboutDialog dlg;
	dlg.set_copyright("Copyright (C) 2007-2008, Net Direct Inc.");
	dlg.set_license(
"    This program is free software; you can redistribute it and/or modify\n"
"    it under the terms of the GNU General Public License as published by\n"
"    the Free Software Foundation; either version 2 of the License, or\n"
"    (at your option) any later version.\n"
"\n"
"    This program is distributed in the hope that it will be useful,\n"
"    but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
"\n"
"    See the GNU General Public License in the COPYING file at the\n"
"    root directory of this project for more details.\n");

	std::vector<std::string> authors;
	authors.push_back("Chris Frey <cdfrey@foursquare.net>");

	dlg.set_authors(authors);

	int major, minor;
	const char *BarryVersion = Barry::Version(major, minor);
	dlg.set_name("Barry Backup");
	dlg.set_version("0.14");
	dlg.set_comments(std::string("Using library: ") + BarryVersion);
	dlg.set_website("http://www.netdirect.ca/software/packages/barry/");
	dlg.run();
}

bool BackupWindow::on_startup()
{
	if( !m_scanned ) {
		ScanAndConnect();
		m_scanned = true;
	}
	return false;
}

void BackupWindow::on_thread_progress()
{
	m_finishedRecords++;
	UpdateProgress();
}

void BackupWindow::on_thread_error()
{
	m_thread_error = true;

	Gtk::MessageDialog msg(m_modeName + " error: " + m_dev.get_last_thread_error());
	msg.run();
}

void BackupWindow::on_thread_done()
{
	if( !m_thread_error ) {
		Gtk::MessageDialog msg(m_modeName + " complete!");
		msg.run();
	}

	// done!
	ClearWorkingMode();
	m_working = false;
}

void BackupWindow::on_thread_erase_db()
{
	std::string name = m_dev.GetThreadDBName();
	m_pDatabaseEntry->set_text("Erasing database: " + name);
}



/*
void on_showtext()
{
	Glib::ustring text = pEntry->get_text();
	Gtk::MessageDialog dialog("This is the text entered: " + text);
//		dialog.set_secondary_text(text);
	dialog.run();
}

void on_close()
{
//		response(Gtk::RESPONSE_CLOSE);
//		signal_delete_event().emit();
//	Gtk::Main::quit();
	hide();
}
*/

