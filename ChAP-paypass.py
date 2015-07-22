#! /usr/bin/env python
"""
Script that tries to select the EMV Payment Systems Directory on all inserted cards.

Copyright 2008 RFIDIOt
Author: Adam Laurie, mailto:adam@algroup.co.uk
    http://rfidiot.org/ChAP.py

This file is based on an example program from scard-python.
  Originally Copyright 2001-2007 gemalto
  Author: Jean-Daniel Aussel, mailto:jean-daniel.aussel@gemalto.com

scard-python is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

scard-python is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with scard-python; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
#import pdb
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.Exceptions import CardRequestTimeoutException

import getopt
import sys
from operator import *
# local imports
from rfidiot.iso3166 import ISO3166CountryCodes
from ChAPlib import * 
from colour import *

#defines for CVV generation technique
MSR = 0
MCHIP = 1

#defines for DDA and SDA support
SDA = 0
DDA = 1
CDA = 2
authsupport = SDA #authsupport: var to hold what the card auth supports

def printhelp():
    print '\nChAP-paypass.py - Chip And PIN in Python, paypass edition'
    print 'Ver 0.1c\n'
    print 'usage:\n\n ChAP-paypass.py [options] [PIN]'
    print
    print 'If the optional numeric PIN argument is given, the PIN will be verified (note that this' 
    print 'updates the PIN Try Counter and may result in the card being PIN blocked).'
    print '\nOptions:\n'
    print '\t-a\t\tBruteforce AIDs'
    print '\t-A\t\tPrint list of known AIDs'
    print '\t-d\t\tDebug - Show PC/SC APDU data'
    print '\t-e\t\tBruteforce EMV AIDs'
    print '\t-f\t\tBruteforce files'
    print '\t-h\t\tPrint detailed help message'
    print '\t-o\t\tOutput to files ([AID]-FILExxRECORDxx.HEX)'
    print '\t-p\t\tBruteforce primitives'
    print '\t-r\t\tRaw output - do not interpret EMV data'
    print '\t-t\t\tUse T1 protocol (default is T0)'
    print '\t-v\t\tVerbose on'
    print '\t-C\t\tCard Mode (MSR or MCHIP)' 
    print

try:
    # 'args' will be set to remaining arguments (if any)
    opts, args  = getopt.getopt(sys.argv[1:],'aAdefoprtvC:')
    for o, a in opts:
        if o == '-a':
            BruteforceAID= True
        if o == '-A':
            print
            for x in range(len(aidlist)):
                print '% 20s: ' % aidlist[x][0],
                hexprint(aidlist[x][1:])
            print
            sys.exit(False) 
        if o == '-d':
            Debug= True
        if o == '-e':
            BruteforceAID= True
            BruteforceEMV= True
        if o == '-f':
            BruteforceFiles= True
        if o == '-o':
            OutputFiles= True
        if o == '-p':
            BruteforcePrimitives= True
        if o == '-r':
            RawOutput= True
        if o == '-t':
            Protocol= CardConnection.T1_protocol
        if o == '-v':
            Verbose= True
        if o == '-C':
            if a == 'MSR':
                CVV = MSR
            elif a == 'MCHIP':
                CVV = MCHIP
except getopt.GetoptError:
    # -h will cause an exception as it doesn't exist!
    printhelp()
    sys.exit(True)

PIN= ''
if args:
    if not args[0].isdigit():
        print 'Invalid PIN', args[0]
        sys.exit(True)
    else:
        PIN= args[0]

try:
    # request any card type
    cardtype = AnyCardType()
    # request card insertion
    print 'insert a card within 10s'
    cardrequest = CardRequest( timeout=10, cardType=cardtype )
    cardservice = cardrequest.waitforcard()

    # attach the console tracer
    if Debug:
        observer=ConsoleCardConnectionObserver()
        cardservice.connection.addObserver( observer )

    # connect to the card
    cardservice.connection.connect(Protocol)

    # try to select PSE
    apdu = SELECT + [len(DF_PSE)] + DF_PSE + [0x00]
    response, sw1, sw2 = send_apdu( apdu, cardservice )

    if check_return(sw1,sw2):
        # there is a PSE
        print 'PSE found!'
        decode_pse(response)
        #get the returned AID 
        status, length, AID = get_tag(response,0x4F)
        status, response, sw1, sw2 = select_aid(AID, cardservice) 
        decode_pse(response)
        status, length, pdol = get_tag(response,0x9F38)
        #get processing options 
        pdollist = list() 
        x = 0
        while x < (len(pdol)): 
            tagstart = x 
            if (pdol[x] & TLV_TAG_NUMBER_MASK) == TLV_TAG_NUMBER_MASK:
                x += 1
                while pdol[x] & TLV_TAG_MASK:
                    x += 1
            x += 1
            taglen = x 
            tag = pdol[tagstart:taglen]  
            #tags = map(hex, tag)
            tags = ["{0:02X}".format(item) for item in tag]
            tags = ''.join(tags)
            tags = int(tags,16) 
            pdollist.append(tags) 
            x += 1
        if CVV == EMV: 
            pdollist = []
            ret, response = get_processing_options(pdollist,cardservice)
        else:
            ret, response = get_processing_options(pdollist,cardservice)
        decode_processing_options(response,cardservice)
        print map(hex,response) 
        if response[4] & 0x20:
            authsupport = DDA
        elif response[4] & 0x40:
            authsupport = SDA
        elif response[4] & 0x01:
            authsupport = CDA
        if CVV == MSR:  
            response = compute_cryptographic_checksum(0, cardservice) 
            decode_pse(response) 
            ret, response = read_record(1,1,cardservice)    
            decode_pse(response) 
            status, length, ktrack1 = get_tag(response,0x9f63)
            status, length, ttrack1 = get_tag(response,0x9f64)
            status, length, ktrack2 = get_tag(response,0x9f66)
            status, length, ttrack2 = get_tag(response,0x9f67)
            d['T1_UNSize'] = calculate_UNsize(listtoint(ktrack1), listtoint(ttrack1))
            d['T2_UNSize'] = calculate_UNsize(listtoint(ktrack2), listtoint(ttrack2))
            print "{green}Track 1 UN Size:\t{yellow}{T1_UNSize}{white}".format(**d)  
            print "{green}Track 2 UN Size:\t{yellow}{T2_UNSize}{white}".format(**d)  
            #print calculate_UNsize(ktrack2, ttrack2)
        if CVV == MCHIP:
            print "RECORD 2 1" 
            ret, response = read_record(2,1,cardservice)    
            decode_pse(response)
            status, length, cvmlist = get_tag(response,0x8e)
            decodeCVM(cvmlist)
            status, length, cdol1 = get_tag(response,0x8c)
            print "RECORD 3 1" 
            ret, response = read_record(3,1,cardservice) 
            decode_pse(response)
            print "RECORD 3 2" 
            ret, response = read_record(3,2,cardservice) 
            decode_pse(response)
            if (authsupport == DDA) | (authsupport == CDA): 
                print "RECORD 4 1" 
                ret, response = read_record(4,1,cardservice) 
                decode_pse(response)
                print "RECORD 4 2" 
                ret, response = read_record(4,2,cardservice) 
                decode_pse(response)
                ICCun = get_challenge(cardservice) #ICC random num
                if(ICCun != None): 
                    TRANS_VAL[0x9f4c] = ICCun
                #generate CDOL list
                cdol1list = list() 
                x = 0
                while x < (len(cdol1)): 
                    tag = '' 
                    tagstart = x 
                    if (cdol1[x] & TLV_TAG_NUMBER_MASK) == TLV_TAG_NUMBER_MASK:
                        x += 1
                        #while cdol1[x] & TLV_TAG_MASK:
                        #    x += 1
                    x += 1
                    taglen = x 
                    tag = cdol1[tagstart:taglen]  
                    #tags = map(hex, tag)
                    tags = ["{0:02X}".format(item) for item in tag]
                    tags = ''.join(tags)
                    tags = int(tags,16) 
                    cdol1list.append(tags) 
                    x += 1  
                print "Generating Application Cryptogram" 
                response = generate_ac(ARQC,True,cdol1list,cardservice)
                decode_pse(response) 
    else:
        print 'no PSE: %02x %02x' % (sw1,sw2)

except CardRequestTimeoutException:
    print 'time-out: no card inserted during last 10s'

if 'win32'==sys.platform:
    print 'press Enter to continue'
    sys.stdin.read(1)
