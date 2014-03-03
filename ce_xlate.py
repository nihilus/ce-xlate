#!/usr/bin/env python

# ce_xlate.py -- ThreatGRID 2014 -- Brandon Mesquita
#
# Chinese-to-English translation.
#
# Decodes GB2312 strings to their UTF8 equivalent and, using CC-CEDICT, display
# a list of possible translations for each symbol.
#
# CC-CEDICT is from MDBG
# http://cc-cedict.org/wiki/
#
# TODO
#       Adapt for use with dictionaries for other languages
#       Option to choose initial string encoding (default GB2312)
#       

from os.path import join,isfile
import idaapi
from idc import GetCommentEx,GetIdaDirectory,GetManyBytes,Message,MakeComm,SetManualInsn
from collections import OrderedDict


class ce_xlatePlugin(idaapi.plugin_t):
    wanted_name = "ce_xlate Translator"
    wanted_hotkey = "Ctrl-R"
    comment = "A simple Chinese to English translator from ThreatGRID."
    help = "ce_xlate Translator - A simple CC-CEDICT based translator from ThreatGRID.\nThanks to MDBG for the CC-CEDICT file: http://www.mdbg.net/chindict/chindict.php?page=cc-cedict"
    flags = 0

    db_loaded = False
    ce_xlate_dictionary = {}
    maxlen = 0

    def init(self):
        return idaapi.PLUGIN_OK

    def term(self):
        pass

    def run(self, arg=0):
        # only load the db if it isn't already loaded
        if not self.db_loaded:
            print("[/] Attempting to load cedict...")
            if not self.load_db():
                print("\n[!] Failed to load the CEDICT file.\n")
                return

        startea = ScreenEA()
        endea, ch_str = self.get_ch_str(startea)
        if endea == -1:
            return

        # search from len to -1 for entries in the dictionary
        translations = self.translate_symbols(startea, ch_str)

        if translations != OrderedDict():
            self.present_message(translations, ch_str)
            #self.present_comment(translations, ch_str)
            self.present_inline(ch_str, startea)

            # Force the bytes into a String
            MakeStr(startea, endea+1)
        return

    def present_message(self, translations, ch_str):
        """
        Print translations of each symbol to the console
        """
        for addr,items in translations.iteritems():
            symbol, deflist = items
            definition = "\n  " + "\n  ".join(deflist)

            Message(symbol)
            Message(definition)
            print ""
            
        Message(ch_str)
        print ""

    def present_comment(self, translations, ch_str):
        """
        We can set comments at the beginning of the string with each symbol and definition
        Be kind to exising comments and do nothing when they're found.
        """
        for addr,items in translations.iteritems():
            symbol, deflist = items
            definition = "\n  " + "\n  ".join(deflist)

            existing_comment = GetCommentEx(addr, 0)
            if not isinstance(existing_comment, str):
                existing_comment = "".join((symbol,definition))
                MakeComm(addr, existing_comment)
    
    def present_inline(self, ch_str, startea):
        """
        Or we can rewrite how each symbol is displayed
        Best to set the first byte to the whole string as only that is displayed
        after stringifying.
        """
        SetManualInsn(startea, ch_str)

    def translate_symbols(self, startea, ch_str):
        """
        Takes the largest available set of symbols and tries to match them to
        entries in the dictionary. Once a valid symbol is found, repeat until
        we reach the end of the string.

        Any valid translations are stored and returned in another dictionary.
        { address_of_symbols: (symbols, (translations)) }
        """
        start_idx = 0
        translations = OrderedDict()

        while (start_idx < len(ch_str)):
            if len(ch_str[start_idx:]) > self.maxlen:
                end_idx = self.maxlen
            else:
                end_idx = len(ch_str[start_idx:])

            while (end_idx and (not self.ce_xlate_dictionary.has_key(ch_str[start_idx:start_idx+end_idx]))):
                end_idx -= 1
            if (end_idx != 0):
                # we have found the string at this point
                symbol = ch_str[start_idx:start_idx+end_idx]
                definitions = self.ce_xlate_dictionary[ch_str[start_idx:start_idx+end_idx]]
                translations[startea+start_idx] = (symbol, definitions)
            else:
                #print("[!] Beginning of the string was not found in the dictionary.")
                end_idx = 1
            start_idx += end_idx
        return translations

    def get_ch_str(self, startea):
        """
        Attempt to grab a full string (currently \x00 terminated) and return a
        tuple of the ending address and the string encoded as UTF-8.

        Decoding occurs here and may need to be adjusted, but we default to
        GB2312.

        Returning an ending address of -1 signifies that the 
        """
        CHUNKSIZE = 2048 # hopefully your string fits in here...
        STRTERM = "\x00" # and ends with this...
        ENCODING = "gb2312" # and is encoded this way...
        ch_str = ""
        endea = -1
        chunk = None

        while chunk is None:
            CHUNKSIZE = CHUNKSIZE >> 1
            chunk = GetManyBytes(startea, CHUNKSIZE)
            if CHUNKSIZE == 0:
                print("[!] Failed to grab any bytes.")
                return (endea, ch_str)

        end_idx = chunk.find(STRTERM)
        if end_idx != -1:
            ch_str = chunk[:end_idx]
            endea = startea + end_idx
        try:
            ch_str = ch_str.decode(ENCODING).encode("utf8")
        except UnicodeDecodeError:
            print("[!] String does not appear to be %s encoded." % ENCODING)
            endea = -1
        return (endea, ch_str)

    def load_db(self):
        """
        This method should only be run once per instance of IDA. It should
        parse the format of the CC-CEDICT file and reduce the contents to a
        dictionary{} with symbols as keys and a list of definitions as values.
        Currently we default to using the Simplified symbols
        
        Traditional Simplified [pin1 yin1] /English equivalent 1/equivalent 2/
           UTF8        UTF8

        See http://cc-cedict.org/wiki/format:syntax for the file format.
        """
        #Try using $IDAHOME/cedict... file first, if it's not found prompt the user.
        ida_dir = GetIdaDirectory()
        filename = join(ida_dir,"cedict_1_0_ts_utf-8_mdbg.txt")
        if not isfile(filename):
            filename = AskFile(0, "*.txt", "Please choose a dictionary file.")

        with open(filename, "r") as ifp:
            for line in ifp.readlines():
                if line.startswith("#"):
                    continue
                ch, eng = line.strip().split("/", 1)
                traditional, simplified, pinyin = ch.split(" ",2)
                self.ce_xlate_dictionary[simplified] = eng.split("/")
                # we track the maximum symbol length to limit the size we use to search for symbols
                if len(simplified) > self.maxlen: self.maxlen = len(simplified)
            self.db_loaded = True
            print("[+] Successfully loaded %d entries." % len(self.ce_xlate_dictionary.keys()))
        return self.db_loaded


def PLUGIN_ENTRY():
    return ce_xlatePlugin()

