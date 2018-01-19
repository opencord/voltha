#OMCI Support

This directory contains classes to assist in the creation, transmission,
and reception of OMCI frames on this ONU Adapter. A number of these files (but
not all) could be moved into the common *.../voltha/extensions/omci* subdirectory.

##Files
### omci_cc.py

The *omci_cc.py* file contains the OMCI communications channel for sending and receiving
OMCI messages.  For transmits, it will send the OMCI message to the proper proxy channel,
but for received, OMCI frames, your device adapter will need to call the
*receive_message()* method.

The communications channel will return a deferred on a Tx request which will fire when
a corresponding response is received or if a timeout or other error occurs. When a
successful response is received, the *OMCI_CC* will also look at *Get, Set, Create*, and
*Delete* messages prior to calling any additional callbacks so that the MIB Database can be
checked or updated as needed.  Note that the MIB Database is not yet implemented.

ONU Autonomous messages are also handled (Test Results messages are TBD) and these are
placed

A collection of statistics are available in case the ONU wishes to publish a
PM group containing these statistics. The Adtran ONU does so in the *onu_pm_metrics.py*
file.

Finally, a list of vendor-specific ME's can be passed to the class initializer so that
they are registered in the class_id map. This allows for successful decode of custom MEs.
See the Adtran ONU's instantiation of the *OMCI_CC* class as an example of how to
add vendor-specific MEs.

### me_frame.py

This file contains the base class implementation that helps to transform defined
Managed EntityClasses into OMCI Frames with specific actions (*get, set, create, 
delete, ...*). Prior this class, frames to do each action were hand created methods.

Besides providing methods for creating OMCI frames, the ME attributes names, access
attributes, and allowed operations are checked to verify that the action is valid
for both the ME as well as the specific attribute.

What is currently missing is other OMCI actions have not been coded:
 - GetNext
 - GetCurrentData
 - GetAllAlarms
 - GetAllAlarmsNext
 - MibUpload
 - MibUploadNext
 - MibReset
 - Test
 - StartSoftwareDownload
 - DownloadSection
 - EndSoftwareDownload
 - ActivateSoftware
 - CommitSoftware
 - SynchronizeTime
 - Reboot
 
For many of these actions, such as MibReset, these are only performed on a specific
ME and it may be best to provide these as explicit static methods.

### omci_me.py

This file is a collection of ME classes derived from the MEFrame base class. For many
of the currently defined ME's in *omci_entities.py*

### omci_defs.py

This file contains an additional status code enumeration which could be merged with
the main OMCI extensions directory.

### omci_entities.py

This is an Adtran ONU specific file to add custom OMCI **OMCI_CC** entities and a function
that can be called by the **OMCI_CC** class to install them into the appropriate locations
such that OMCI frame decode works as expected during MIB uploads.

Eventually I envision the **OMCI_CC** to be mostly hidden from an ONU device adapter, so
a method to register these custom ME's needs to be provided.
 
### deprecated.py

This file contains some of the original _old-style_ OMCI frame creation and send
commands for the Adtran ONU. These were originally copied over from the BroadCom
ONU Device Adapter and modified for use in the Adtran ONU. After the **OMCI_CC** class
was created to handle OMCI Tx/Rx, a reference to the **OMCI_CC** was passed in so that
these methods could use the *OMCI_CC.send()* method

If you look at the current Adtran ONU **pon_port.py** file, it still contains the original
calls to these are still in place (commented out) next to how to do the same calls with
the new **ME_Frame** and **OMCI_CC** classes.

##Unit Tests

After some peer review and any needed refactoring of code, the plan is to create unit tests
to cover the **OMCI_CC** and **ME_Frame** classes with a target of _90%+_ line coverage.