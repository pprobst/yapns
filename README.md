# yapns
- yet another python network scanner

### Dependencies
* Python 3
* [manuf](https://github.com/coolbho3k/manuf)
* [scapy](https://github.com/secdev/scapy)

### Running
First, make sure that the script ```run``` is executable in your sistem.

Then,

```
$ ./run scan_interval_in_seconds
```

The file ```clients.csv``` contains a simple history of the discovered devices.

### Observations
* Tested only on GNU/Linux. Surely incompatible with Windows.
* This program is not meant to be the most efficient possible -- it was
  originally a university assignment that was interesting enough to post here.
  Plus, it was fun writing it.
* Yes, similar information could've been retrieved with some UNIX programs.
