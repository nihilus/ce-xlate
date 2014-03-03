ce-xlate
========

## Chinese language translator for IDA Pro

This plugin assists in the analysis of binaries with GB2312-encoded strings.
The plugin will attempt to offer possible translations and display the GB2312 bytes as UTF8 symbols that can be displayed within IDA.

## Installation

Download the latest [CC-CEDICT library file](http://www.mdbg.net/chindict/chindict.php?page=cc-cedict) from [MDBG](http://cc-cedict.org/wiki/).

Download this plugin and copy it to your $IDAdirectory/plugins/

## Usage

The plugin tries to bind Ctrl+R.

Pressing this key the first time will prompt for the location of the CC-CEDICT file if it does not exist in your $IDAdirectory/.
Subsequent presses will cause the bytes currently pointed to by IDA's cursor to be examined, possibly translated, and redisplayed as UTF8-encoded Simplified Chinese.

IDA's custom instruction capability is used for the changed display and can be manually reverted.

