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
                reset_pin_try_counter(apdu);  // Laboratory 4 - Task 1	
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    } // end of process method

    private void credit(APDU apdu) {

        // Require successful PIN verification
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

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

    
    private void debit (APDU apdu)
    {
        // Require PIN verification.
        if (!pin.isValidated())
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

        byte[] buffer = apdu.getBuffer();
        
        // Payment method indicator
        byte p1 = buffer[ISO7816.OFFSET_P1];
        
        byte numBytes = buffer[ISO7816.OFFSET_LC];
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // Process according to payment method
        if (p1 == 0x01)
        {
        	// RON only
        	
            if ((numBytes != 1) || (byteRead != 1))
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            
            byte debitAmount = buffer[ISO7816.OFFSET_CDATA];
            
            if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0))
                ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
            
            if ((short)(balanceRON - debitAmount) < 0)
                ISOException.throwIt(SW_NEGATIVE_BALANCE);
            
            balanceRON = (short)(balanceRON - debitAmount);
            
            // Award loyalty points: 1 point for every 20 RON spent.
            byte pointsEarned = (byte)(debitAmount / 20);
            int newPoints = balanceLoyaltyPoints + pointsEarned;
            balanceLoyaltyPoints = (short)((newPoints > MAX_LOYALTY_POINTS) ? MAX_LOYALTY_POINTS : newPoints);
        }
        else if (p1 == 0x02)
        {
        	// Points only
        	
            if ((numBytes != 1) || (byteRead != 1))
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            
            byte debitPoints = buffer[ISO7816.OFFSET_CDATA];
            
            if ((debitPoints > MAX_TRANSACTION_AMOUNT) || (debitPoints < 0))
                ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
            
            if ((short)(balanceLoyaltyPoints - debitPoints) < 0)
                ISOException.throwIt(SW_NEGATIVE_BALANCE);
            
            balanceLoyaltyPoints = (short)(balanceLoyaltyPoints - debitPoints);
        }
        else if (p1 == 0x03)
        {
        	// Combination payment
        	
            if ((numBytes != 2) || (byteRead != 2))
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            
            byte ronPart = buffer[ISO7816.OFFSET_CDATA];
            byte pointsPart = buffer[(short)(ISO7816.OFFSET_CDATA + 1)];
            int totalAmount = (ronPart & 0xFF) + (pointsPart & 0xFF);
            
            if ((totalAmount > MAX_TRANSACTION_AMOUNT) || (totalAmount < 0))
                ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
            
            if ((short)(balanceRON - ronPart) < 0)
                ISOException.throwIt(SW_NEGATIVE_BALANCE);
            
            if ((short)(balanceLoyaltyPoints - pointsPart) < 0)
                ISOException.throwIt(SW_NEGATIVE_BALANCE);
            
            balanceRON = (short)(balanceRON - ronPart);
            balanceLoyaltyPoints = (short)(balanceLoyaltyPoints - pointsPart);
            
            // Award loyalty points for the RON portion (if any).
            byte pointsEarned = (byte)(ronPart / 20);
            int newPoints = balanceLoyaltyPoints + pointsEarned;
            balanceLoyaltyPoints = (short)((newPoints > MAX_LOYALTY_POINTS) ? MAX_LOYALTY_POINTS : newPoints);
        }
        else
        {
            // Unknown payment method
        	
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    
    private void getBalance (APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        
        // Expect one byte indicating which balance to return: 0x01 = RON, 0x02 = loyalty points.
        
        byte numBytes = buffer[ISO7816.OFFSET_LC];
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        
        if ((numBytes != 1) || (byteRead != 1))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        byte option = buffer[ISO7816.OFFSET_CDATA];
        
        short balanceToReturn;
        
        if (option == 0x01)
            balanceToReturn = balanceRON;
        
        else if (option == 0x02)
            balanceToReturn = balanceLoyaltyPoints;
        
        else
        {
            // Undefined option
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            return;
        }
        
        short le = apdu.setOutgoing();
        
        if (le < 2)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        buffer[0] = (byte)(balanceToReturn >> 8);
        buffer[1] = (byte)(balanceToReturn & 0xFF);
        
        apdu.setOutgoingLength((byte)2);
        apdu.sendBytes((short)0, (short)2);
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

} // end of class Wallet
