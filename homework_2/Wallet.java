package com.oracle.jcclassic.samples.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

public class Wallet extends Applet {

    /* constants declaration */

    // code of CLA byte in the command APDU header
    final static byte Wallet_CLA = (byte) 0x80;

    // codes of INS byte in the command APDU header
    final static byte VERIFY        = (byte) 0x20;
    final static byte CREDIT        = (byte) 0x30;
    final static byte DEBIT         = (byte) 0x40;
    final static byte GET_BALANCE   = (byte) 0x50;
    final static byte RESET_PIN     = (byte) 0x2C;         // Laboratory 4 - Task 2
    final static byte PASS          = (byte) 0x70;         // Transport pass

    // maximum balance
    final static short MAX_BALANCE = 0x7FFF;
    // maximum transaction amount
    final static int MAX_TRANSACTION_AMOUNT = 1000;
    // maximum number of loyalty points
    final static int MAX_LOYALTY_POINTS = 300;

    // subscription constants
    final static byte SUB_NONE         = (byte)0x00;
    final static byte SUB_BUS          = (byte)0x01;
    final static byte SUB_TRAM         = (byte)0x02;
    final static short BUS_TRIP_PRICE  = 4;
    final static short TRAM_TRIP_PRICE = 2;
    final static short BUS_PASS_COST   = 60;
    final static short TRAM_PASS_COST  = 40;
    final static byte BUS_PASS_TRIPS   = 20;
    final static byte TRAM_PASS_TRIPS  = 30;

    // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED         = 0x6300;
    // signal the the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED   = 0x6301;
    // signal invalid transaction amount
    // amount > MAX_TRANSACTION_AMOUNT or amount < 0
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;
    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE     = 0x6A84;
    // signal the balance becomes negative or insufficient funds
    final static short SW_NEGATIVE_BALANCE           = 0x6A85;
    // signal no subscription available
    final static short SW_NO_SUBSCRIPTION_AVAILABLE  = 0x6A86;
    // signal too many tickets requested
    final static short SW_TOO_MANY_TICKETS           = 0x6A87;

    /* instance variables declaration */
    OwnerPIN pin;
    short balanceRON;            // RON balance
    short balanceLoyaltyPoints;  // Loyalty points balance

    // transport subscription state
    byte subType;                // 0=none, 1=bus, 2=tram
    byte subRemainingTrips;

    private final byte[] pukCode = {0x09,0x09,0x09,0x09,0x09,0x09,0x09,0x09};

    private Wallet(byte[] bArray, short bOffset, byte bLength) {
        // Allocate all memory needed during applet lifetime in the constructor
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        byte iLen = bArray[bOffset]; // AID length
        bOffset = (short)(bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short)(bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length

        // The installation parameters contain the PIN initialization value
        pin.update(bArray, (short)(bOffset + 1), aLen);

        // initialize balances
        balanceRON = 0;
        balanceLoyaltyPoints = 0;
        subType = SUB_NONE;
        subRemainingTrips = 0;

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Wallet(bArray, bOffset, bLength);
    }

    @Override
    public boolean select() {
        // Decline selection if the PIN is blocked.
        return pin.getTriesRemaining() != 0;
    }

    @Override
    public void deselect() {
        // reset the PIN value
        pin.reset();
    }

    @Override
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // Check for SELECT APDU command
        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte)0xA4) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        // Verify that commands have the correct CLA
        if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        switch (buffer[ISO7816.OFFSET_INS]) {
            case VERIFY:        verify(apdu);                  return;
            case CREDIT:        credit(apdu);                  return;
            case DEBIT:         debit(apdu);                   return;
            case PASS:          pass(apdu);                    return;
            case GET_BALANCE:   getBalance(apdu);              return;
            case RESET_PIN:     reset_pin_try_counter(apdu);   return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void verify(APDU apdu) {
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte)apdu.setIncomingAndReceive();
        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead)) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    }

    private void credit(APDU apdu) {
        // Require successful PIN verification
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        byte[] buffer = apdu.getBuffer();
        byte numBytes = buffer[ISO7816.OFFSET_LC];
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        if ((numBytes != 1) || (byteRead != 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte creditAmount = buffer[ISO7816.OFFSET_CDATA];
        if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }
        if ((short)(balanceRON + creditAmount) > MAX_BALANCE) {
            ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
        }
        balanceRON = (short)(balanceRON + creditAmount);
    }

    private void pass(APDU apdu) {
        // Subscription purchase
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        byte[] buffer = apdu.getBuffer();
        byte type = buffer[ISO7816.OFFSET_P1];
        if (subType != SUB_NONE) {
            ISOException.throwIt(SW_NO_SUBSCRIPTION_AVAILABLE);
        }
        short cost;
        byte trips;
        if (type == SUB_BUS) {
            cost = BUS_PASS_COST;
            trips = BUS_PASS_TRIPS;
        } else if (type == SUB_TRAM) {
            cost = TRAM_PASS_COST;
            trips = TRAM_PASS_TRIPS;
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            return;
        }
        if ((short)(balanceRON - cost) < 0) {
            ISOException.throwIt(SW_NEGATIVE_BALANCE);
        }
        balanceRON -= cost;
        subType = type;
        subRemainingTrips = trips;
    }

    private void debit(APDU apdu) {
        // Ticket purchase or subscription use
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        byte[] buffer = apdu.getBuffer();
        byte mode = buffer[ISO7816.OFFSET_P1];
        byte flag = buffer[ISO7816.OFFSET_P2];
        byte numBytes = buffer[ISO7816.OFFSET_LC];
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        if ((numBytes != 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte count = buffer[ISO7816.OFFSET_CDATA];
        if (count < 1 || count > 20) {
            ISOException.throwIt(SW_TOO_MANY_TICKETS);
        }
        // Use subscription if valid
        if (count == 1 && subType == mode && subRemainingTrips > 0) {
            subRemainingTrips--;
            return;
        }
        // Determine unit price
        short unit;
        if (flag == 1) {
            unit = (mode == SUB_BUS) ? (short)3 : (short)1; // morning discount
        } else if (flag == 2) {
            short base = (mode == SUB_BUS) ? BUS_TRIP_PRICE : TRAM_TRIP_PRICE;
            unit = (short)(base / 2); // weekend discount
        } else {
            unit = (mode == SUB_BUS) ? BUS_TRIP_PRICE : TRAM_TRIP_PRICE;
        }
        short total = (short)(unit * count);
        // group discount
        if (count > 10) {
            total = (short)((total * 80) / 100);
        }
        if (total > balanceRON) {
            ISOException.throwIt(SW_NEGATIVE_BALANCE);
        }
        balanceRON -= total;
    }

    private void getBalance(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte numBytes = buffer[ISO7816.OFFSET_LC];
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        short le = apdu.setOutgoing();
        if (le < 3) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        buffer[0] = (byte)(balanceRON >> 8);
        buffer[1] = (byte)(balanceRON & 0xFF);
        buffer[2] = subRemainingTrips;
        apdu.setOutgoingLength((byte)3);
        apdu.sendBytes((short)0, (short)3);
    }

    private void reset_pin_try_counter(APDU apdu) {
        if (pin.getTriesRemaining() == 0) {
            byte[] buffer = apdu.getBuffer();
            byte byteRead = (byte)(apdu.setIncomingAndReceive());
            if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, pukCode, (short)0, (short)8) == 0) {
                pin.resetAndUnblock();
            } else {
                ISOException.throwIt(SW_VERIFICATION_FAILED);
            }
        }
    }

} // end of class Wallet