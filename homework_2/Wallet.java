/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 */

/*
 */

/*
 * @(#)Wallet.java 1.11 06/01/03
 */

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
    final static byte VERIFY = (byte) 0x20;
    final static byte CREDIT = (byte) 0x30;
    final static byte DEBIT = (byte) 0x40;
    final static byte GET_BALANCE = (byte) 0x50;
    final static byte RESET_PIN = (byte) 0x2C;         // Laboratory 4 - Task 2

    // maximum balance
    final static short MAX_BALANCE = 0x7FFF;
    // maximum transaction amount
    final static int MAX_TRANSACTION_AMOUNT = 1000;
    // maximum number of loyalty points
    final static int MAX_LOYALTY_POINTS = 300;

    // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    // signal the the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    // signal invalid transaction amount
    // amount > MAX_TRANSACTION_AMOUNT or amount < 0
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;
    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    // signal the balance becomes negative or insufficient funds
    final static short SW_NEGATIVE_BALANCE = 0x6A85;
    
    
    
    // Homework 2
    
    // Price of a bus ticket (4 RON).
    private static final short BUS_TICKET_PRICE = 4;
    
    // Price of a tram ticket (2 RON).
    private static final short TRAM_TICKET_PRICE = 2;
    
    // Price of a bus pass (60 RON).
    private static final short BUS_PASS_PRICE = 60;
    
    // Price of a tram pass (40 RON).
    private static final short TRAM_PASS_PRICE = 40;
    
    // Number of trips of a bus pass (20 trips).
    private static final byte BUS_PASS_NUMBER_OF_TRIPS = 20;
    
    // Number of trips of a tram pass (30 trips).
    private static final byte TRAM_PASS_NUMBER_OF_TRIPS = 30;
    
    // Status code for no pass (code 27,270).
    private static final short SW_NO_PASS = (short) 0x6A86;
    
    // Status code for too many tickets (code 27,271).
    private static final short SW_TOO_MANY_TICKETS = (short) 0x6A87;
    
    // Pass type - none (0).
    private static final byte PASS_TYPE_NONE = (byte) 0x00;
    
    // Pass type - bus (1).
    private static final byte PASS_TYPE_BUS = (byte) 0x01;
    
    // Pass type - tram (2).
    private static final byte PASS_TYPE_TRAM = (byte) 0x02;
    
    // Pass type (0 - none, 1 - bus, 2 - tram).
    private byte passType;
    
    // Number of remaining trips for the pass.
    private byte passRemainingNumberOfTrips;
    
    // INS code for purchasing a pass.
    final static byte PURCHASE_PASS = (byte) 0x70;


    
    /* instance variables declaration */
    OwnerPIN pin;
    short balanceRON;            // RON balance
    short balanceLoyaltyPoints;  // Loyalty points balance
    private final byte[] pukCode = {0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09}; 

    private Wallet(byte[] bArray, short bOffset, byte bLength) {

        // Allocate all memory needed during applet lifetime in the constructor
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        byte iLen = bArray[bOffset]; // AID length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length

        // The installation parameters contain the PIN initialization value
        pin.update(bArray, (short) (bOffset + 1), aLen);
        
        
        
        // Homework 2
        
        // By default, the user has no pass.
        passType = PASS_TYPE_NONE;
        
        // Because by default the user has no pass, the number of remaining trips is 0.
        passRemainingNumberOfTrips = 0;
        
        
        
        register();
    } // end of constructor

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Wallet(bArray, bOffset, bLength);
    } // end of install method

    @Override
    public boolean select() {
        // Decline selection if the PIN is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }
        return true;
    } // end of select method

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
            if (buffer[ISO7816.OFFSET_INS] == (byte) 0xA4) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Verify that commands have the correct CLA
        if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case GET_BALANCE:
                getBalance(apdu);
                return;
            case DEBIT:
                debit(apdu);
                return;
            case CREDIT:
                credit(apdu);
                return;
            case VERIFY:
                verify(apdu);
                return;
            case RESET_PIN:
                reset_pin_try_counter(apdu);  	// Laboratory 4 - Task 1	
                return;
            case PURCHASE_PASS:
            	pass(apdu);						// Homework 2
            	return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    } // end of process method

    private void credit(APDU apdu)
    {
        // Validate the PIN number.
        if (!pin.isValidated())
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

        byte[] buffer = apdu.getBuffer();
        byte numBytes = buffer[ISO7816.OFFSET_LC];
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

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
    } // end of credit method

    
    
    // Homework 2
    
    private void debit (APDU apdu)
    {
    	// Get the means of transport (1 - bus, 2 - tram).
        byte[] apduBuffer = apdu.getBuffer();
        byte meansOfTransport = apduBuffer[ISO7816.OFFSET_P1];
        
        // Get the fare type (1 - morning, 2 - weekend, otherwise full price).
        byte fareType = apduBuffer[ISO7816.OFFSET_P2];

        // Make sure the number of tikets is exactly one byte.
        byte numberOfBytes = apduBuffer[ISO7816.OFFSET_LC];
        byte numberOfReadBytes = (byte)apdu.setIncomingAndReceive();
        
        if (numberOfBytes != 1 || numberOfReadBytes != 1)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        // Get the number of tickets.
        byte numberOfTickets = apduBuffer[ISO7816.OFFSET_CDATA];
        byte numberOfTicketsToPay = numberOfTickets;
        
        // If the user has a matching pass and at least one trip left, consume that one trip from the pass.
        if (passType == meansOfTransport && passRemainingNumberOfTrips > 0)
        {
            passRemainingNumberOfTrips--;
            numberOfTicketsToPay--;
        }

        // If no tickets need to be paid, return early.
        if (numberOfTicketsToPay == 0)
            return;
        
        // Otherwise, compute unit price.
        short unitPrice;
        
        // Morning Fare
        if (fareType == 0x01)
            unitPrice = (meansOfTransport == PASS_TYPE_BUS) ? (short)3 : (short)1;
        
        // Weekend Fare
        else if (fareType == 0x02)
        {
            short base = (meansOfTransport == PASS_TYPE_BUS) ? BUS_TICKET_PRICE : TRAM_TICKET_PRICE;
            unitPrice = (short)(base / 2);
        }
        
        // Full Fare
        else
            unitPrice = (meansOfTransport == PASS_TYPE_BUS) ? BUS_TICKET_PRICE : TRAM_TICKET_PRICE;
        
        // Make sure you don't try to buy less than 1 ticket or more than 20.
        if (numberOfTickets < 1 || numberOfTickets > 20)
            ISOException.throwIt(SW_TOO_MANY_TICKETS);
        
        // Compute the total.
        short totalPrice = (short)(unitPrice * numberOfTicketsToPay);
        
        // Get a group discount (20% off).
        if (numberOfTicketsToPay > 10)
        	totalPrice = (short)((totalPrice * 80) / 100);
        
        // Make sure you have enough money for the tickets.
        if (totalPrice > balanceRON)
            ISOException.throwIt(SW_NEGATIVE_BALANCE);
        
        // Update the balance.
        balanceRON -= (short)totalPrice;
    }

    

    // Homework 2
    
    private void getBalance (APDU apdu)
    {
        byte[] apduBuffer = apdu.getBuffer();

        // How many bytes the terminal expects
        short expectedNumberOfBytes = apdu.setOutgoing();
        
        // The expected number of bytes must be 3: 2 for the balance, 1 for the remaining number of trips.
        if (expectedNumberOfBytes < 3)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // Get the balance.
        apduBuffer[0] = (byte)(balanceRON >> 8);
        apduBuffer[1] = (byte)(balanceRON & 0xFF);

        // Get the remaining number of trips.
        apduBuffer[2] = passRemainingNumberOfTrips;

        // Set the number of bytes of the result to be sent (3: 2 for the balance, 1 for the remaining number of trips).
        apdu.setOutgoingLength((byte)3);
        
        // Send the results.
        apdu.sendBytes((short)0, (short)3);
    }

    
    
    private void verify(APDU apdu) {

        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
           
        byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    } // end of verify method
    
    // Laboratory 4 - Task 2
    private void reset_pin_try_counter(APDU apdu) {
        if (pin.getTriesRemaining() == 0) {  
            byte[] buffer = apdu.getBuffer();
            byte offsetCData = ISO7816.OFFSET_CDATA;
            if (Util.arrayCompare(buffer, offsetCData, pukCode, (short)0, (short)8) == 0) {
                pin.resetAndUnblock();
            } else {
                ISOException.throwIt(SW_VERIFICATION_FAILED);
            }
        }
    } // end of reset_pin_try_counter method
    
    
    
    // Homework 2

    private void pass (APDU apdu)
    {
        // Get the pass type.
        byte[] apduBuffer = apdu.getBuffer();
        byte passTypeLocal = apduBuffer[ISO7816.OFFSET_P1];

        // Make sure no other pass is active at the moment.
        if (passType != PASS_TYPE_NONE)
            ISOException.throwIt(SW_NO_PASS);

        short passPrice;
        byte passNumberOfTrips;
        
        // Pass Type - Bus
        if (passTypeLocal == PASS_TYPE_BUS)
        {
            passPrice = BUS_PASS_PRICE;
            passNumberOfTrips = BUS_PASS_NUMBER_OF_TRIPS;
        }
        
        // Pass Type - Tram
        else if (passTypeLocal == PASS_TYPE_TRAM)
        {
        	passPrice  = TRAM_PASS_PRICE;
            passNumberOfTrips = TRAM_PASS_NUMBER_OF_TRIPS;
        }
        
        // Pass Type - Something Else
        else
        {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            return;
        }

        // Make sure there is enough money to pay for the pass.
        if (balanceRON < passPrice)
            ISOException.throwIt(SW_NEGATIVE_BALANCE);

        // Update the balance.
        balanceRON -= passPrice;
        
        // Set the pass type.
        passType = passTypeLocal;
        
        // Update the remaining number of trips.
        passRemainingNumberOfTrips = passNumberOfTrips;
    }
    
    
    
} // end of class Wallet