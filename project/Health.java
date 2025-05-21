package health;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;



public class Health extends Applet
{
    // Define the code for the class of instructions.
    final static byte CLA_HEALTH 					= (byte) 0x80;		// code =   128
    
    
    // Define the codes for the instructions.
    final static  byte INS_VERIFY 					= (byte) 0x20;		// code =    32
    final static  byte INS_UPDATE_PIN       		= (byte) 0x24;		// code =    36
    final static  byte INS_GET_PATIENT_DATA			= (byte) 0x30;		// code =    48
    final static  byte INS_SET_PATIENT_DATA			= (byte) 0x40;		// code =    64
    final static  byte INS_SET_CONSULT_DATA			= (byte) 0x50;		// code =    80
    final static  byte INS_SET_MED_VACATION			= (byte) 0x60;		// code =    96

    
    // Define the codes for the possible errors.
    final static short SW_VERIFICATION_FAILED 		= 		 0x6300;	// code = 25344
    final static short SW_NOT_ENOUGH_DATA     		= 		 0x6A80;	// code = 27264
    final static short SW_CONDITIONS_NOT_SATISFIED	= 		 0x6985;	// code = 27013

    
    // Define the limits for the PIN of the user.
    final static  byte PIN_MAXIMUM_NUMBER_OF_TRIES 	= (byte) 0x03;		// code = 	  3
    final static  byte PIN_MAXIMUM_SIZE  			= (byte) 0x08;		// code = 	  8

    
    // Declare the cryptography variables.
    private AESKey aesKey;
    private Cipher aesCipher;
    
    
    // Declare the PIN of the user.
    private OwnerPIN pin;

    
    // Declare the data for the patient.
    // Layout:
    // 		-  [0] - birthdate - day
    //		-  [1] - birthdate - month
    //		-  [2] - birthdate - year
    // 		-  [3] - blood group
    // 		-  [4] - Rh factor
    // 		-  [5] - chronic diagnosis code
    // 		-  [6] - chronic specialty code
    // 		-  [7] - donor code (0 = no, 1 = yes)
    //   	-  [8] – consult 1 - diagnosis code
    //   	-  [9] – consult 1 - specialty code
    //  	- [10] – consult 1 - date - day
    //  	- [11] – consult 1 - date - month
    //  	- [12] – consult 1 - date - year
    //  	- [13] – consult 2 - diagnosis code
    //  	- [14] – consult 2 - specialty code
    //  	- [15] – consult 2 - date - day
    //  	- [16] – consult 2 - date - month
    //  	- [17] – consult 2 - date - year
    //  	- [18] – consult 3 - diagnosis code
    //  	- [19] – consult 3 - specialty code
    //  	- [20] – consult 3 - date - day
    //  	- [21] – consult 3 - date - month
    //  	- [22] – consult 3 - date - year
    //  	- [23] – last medical vacation - start date - day
    //  	- [24] – last medical vacation - start date - month
    //  	- [25] – last medical vacation - start date - year
    //  	- [26] – last medical vacation - end date - day
    // 		- [27] – last medical vacation - end date - month
    //  	- [28] – last medical vacation - end date - year
    private byte[] patientData;

    
    private Health (byte[] bArray, short bOffset, byte bLength)
    {
        // Initialize the PIN of the user.
        pin = new OwnerPIN(PIN_MAXIMUM_NUMBER_OF_TRIES, PIN_MAXIMUM_SIZE);
        
        // Get the size of the PIN of the user.
        byte pinLength = bArray[(short)(bOffset)];
        
        // Set the PIN of the user.
        pin.update(bArray, (short)(bOffset + 1), pinLength);
        
        // Get the offset of the AES key.
        short aesKeyOffset = (short)(bOffset + 1 + pinLength);
        
        // Create the AES key.
        aesKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        
        // Set the AES key.
        aesKey.setKey(bArray, aesKeyOffset);
        
        // Set the AES cipher.
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        // Declare the data of the patient.
        patientData = new byte[29];

        // Finalize the applet installation.
        register();
    }

    
    public static void install (byte[] bArray, short bOffset, byte bLength)
    {
    	// Install the applet.
        new Health(bArray, bOffset, bLength);
    }

    
    @Override
    public boolean select ()
    {
    	// Select the applet if the remaining number of tries for the PIN is at least 1.
        return pin.getTriesRemaining() > 0;
    }

    
    @Override
    public void deselect ()
    {
    	// Reset the PIN to deselect the applet.
        pin.reset();
    }

    
    @Override
    public void process (APDU apdu)
    {
    	// Get the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();
        
        // If the given command is to select the applet, the job is done.
        if (selectingApplet())
        	return;

        // Check is the CLA is the correct one. If not, stop.
        if (apduBuffer[ISO7816.OFFSET_CLA] != CLA_HEALTH)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        // Manage the commands.
        switch (apduBuffer[ISO7816.OFFSET_INS])
        {
        	// Validate the PIN of the user.
            case INS_VERIFY:
                verify(apdu);
                break;
                
            // Change the PIN of the user.
            case INS_UPDATE_PIN:
                requireVerified();
                updatePin(apdu);
                break;
                
            // Get the data of the patient.
            case INS_GET_PATIENT_DATA:
                requireVerified();
                getPatientData(apdu);
                break;
                
            // Sets the data of the patient.
            case INS_SET_PATIENT_DATA:
                requireVerified();
                setPatientData(apdu);
                break;
                
            // Set the data of the new consult.
            case INS_SET_CONSULT_DATA:
                requireVerified();
                setConsultData(apdu);
                break;
                
            // Set the data for the medical vacation.
            case INS_SET_MED_VACATION:
                requireVerified();
                setMedicalVacation(apdu);
                break;
                
            // If any other command, refuse it.
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    
    private void requireVerified ()
    {
    	// Check if the PIN of the user is the correct one.
        if (!pin.isValidated())
            ISOException.throwIt(SW_VERIFICATION_FAILED);
    }


    private void verify (APDU apdu)
    {
    	// Get the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();
        
        // Get the length of the APDU.
        short apduLength = apdu.setIncomingAndReceive();
        
        // Validate the length of the APDU.
        if (apduLength != 32)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        short initializationVectorOffset = ISO7816.OFFSET_CDATA;
        short ciphertextOffset = (short)(initializationVectorOffset + 16);
        
        // Decrypt the PIN.
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT, apduBuffer, initializationVectorOffset, (short)16);
        aesCipher.doFinal(apduBuffer, ciphertextOffset, (short)16, apduBuffer, (short)0);
        
        // Get the length of the PIN.
        byte pinLength = 0;
        
        while (pinLength < PIN_MAXIMUM_SIZE && apduBuffer[pinLength] != 0)
        	pinLength++;
        
        // Validate the PIN of the user.
        if (!pin.check(apduBuffer, (short)0, pinLength))
        	ISOException.throwIt(SW_VERIFICATION_FAILED);
    }

    
    private void updatePin (APDU apdu)
    {
    	// Get the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();
        
        // Get the length of the APDU.
        short apduLength = apdu.setIncomingAndReceive();
        
        // Make sure there is enough room for both the old and the new PINs of the user.
        if (apduLength < (short)(PIN_MAXIMUM_SIZE * 2))
        	ISOException.throwIt(SW_NOT_ENOUGH_DATA);
        
        // Validate the current PIN of the user.
        if (!pin.check(apduBuffer, ISO7816.OFFSET_CDATA, PIN_MAXIMUM_SIZE))
        	ISOException.throwIt(SW_VERIFICATION_FAILED);
        
        // Update the PIN of the user.
        pin.update(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PIN_MAXIMUM_SIZE), PIN_MAXIMUM_SIZE);
    }

    
    private void getPatientData (APDU apdu)
    {
        apdu.setOutgoing();
        
        // Get the length of the data.
        apdu.setOutgoingLength((short)patientData.length);
        
        // Get the data of the patient.
        apdu.sendBytesLong(patientData, (short)0, (short)patientData.length);
    }

    
    private void setPatientData (APDU apdu)
    {
    	// Get the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();
        
        // Get the length of the APDU.
        apdu.setIncomingAndReceive();
        
        // Get the option (0 = chronic diagnosis, 1 = chronic specialty, 2 = donor code).
        byte option = apduBuffer[ISO7816.OFFSET_P1];
        
        // Get the value corresponding to the given option.
        byte value = apduBuffer[ISO7816.OFFSET_CDATA];
        
        switch (option)
        {
        	// Set the chronic diagnosis.
            case 0:
            	patientData[5] = value;
            	break;
            	
            // Set the chronic specialty.
            case 1:
            	patientData[6] = value;
            	break;
            	
            // Set the donor code.
            case 2:
            	patientData[7] = value;
            	break;
            	
            // If other option, reject it.
            default:
            	ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    
    private void setConsultData (APDU apdu)
    {
    	// Get the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();
        
        // Get the length of the APDU.
        short apduLength = apdu.setIncomingAndReceive();
        
        // Get the diagnosis code.
        byte diagnosisCode = apduBuffer[ISO7816.OFFSET_P1];
        
        // Get the specialty code.
        byte specialtyCode = apduBuffer[ISO7816.OFFSET_P2];
        
        // Ensure the correct length of the command.
        if (apduLength != 3)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        // Get the day.
        byte day = apduBuffer[ISO7816.OFFSET_CDATA];
        
        // Get the month.
        byte month = apduBuffer[ISO7816.OFFSET_CDATA + 1];
        
        // Get the year.
        byte year = apduBuffer[ISO7816.OFFSET_CDATA + 2];
        
        // Check if the patient has a chronic disease.
        boolean isChronic = (patientData[5] != 0);
        
        // Check if the patient has a chronic disease at the requested specialty.
        boolean isChronicEligible = (isChronic && patientData[6] == specialtyCode);

        // Check if the patient didn't go to another consult this month at the requested specialty.
        boolean noRepeatThisMonth = true;
        
        if (!isChronic)
            for (short entry = 0; entry < 3; entry++)
            {
                short base = (short)(8 + entry * 5);
                byte oldSpecialty = patientData[(short)(base + 1)];
                byte oldMonth     = patientData[(short)(base + 3)];
                
                if (oldSpecialty == specialtyCode && oldMonth == month)
                {
                    noRepeatThisMonth = false;
                    break;
                }
            }

        // Ensure the eligibility status.
        if (!(isChronicEligible || (!isChronic && noRepeatThisMonth)))
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

        // Rotate the three oldest consults.
        Util.arrayCopy(patientData, (short)13, patientData, (short)8, (short)10);

	    // Get the offset of the new consult to be added.
	    short position = (short)(8 + 2 * 5);
     
     	// Set the new data of the patient.
        patientData[position]   		   = diagnosisCode;
        patientData[(short)(position + 1)] = specialtyCode;
        patientData[(short)(position + 2)] = day;
        patientData[(short)(position + 3)] = month;
        patientData[(short)(position + 4)] = year;
    }

    
    // SET MEDICAL VACATION: data 6 bytes start(3) and end(3)
    private void setMedicalVacation (APDU apdu)
    {
    	// Get the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();
        
        // Get the length of the APDU.
        short apduLength = apdu.setIncomingAndReceive();
        
        // Ensure the length of the APDU.
        if (apduLength != 6)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        // Extract the new vacation dates.
        byte newStartDay   = apduBuffer[ISO7816.OFFSET_CDATA];
        byte newStartMonth = apduBuffer[(short)(ISO7816.OFFSET_CDATA + 1)];
        byte newStartYear  = apduBuffer[(short)(ISO7816.OFFSET_CDATA + 2)];
        byte newEndDay     = apduBuffer[(short)(ISO7816.OFFSET_CDATA + 3)];
        byte newEndMonth   = apduBuffer[(short)(ISO7816.OFFSET_CDATA + 4)];
        byte newEndYear    = apduBuffer[(short)(ISO7816.OFFSET_CDATA + 5)];

        // Check if the patient has a chronic disease.
        boolean isChronic = (patientData[5] != 0);
        
        if (!isChronic)
        {
            byte oldStartDay   = patientData[23];
            byte oldStartMonth = patientData[24];
            byte oldStartYear  = patientData[25];
            byte oldEndDay     = patientData[26];
            // byte oldEndMonth   = patientData[27];
            // byte oldEndYear    = patientData[28];

            short alreadyDays = 0;
            
            // Check if the it's the same month and year.
            if (oldStartMonth == newStartMonth && oldStartYear == newStartYear)
                alreadyDays = (short)(oldEndDay - oldStartDay + 1);
            
            short newDays = 0;
            
            if (oldStartMonth == newStartMonth)
                newDays = (short)(newEndDay - newStartDay + 1);
            
            else
                newDays = (short)(getDaysInMonth(newStartMonth, newStartYear) - newStartDay + 1);
            
            if ((short)(alreadyDays + newDays) > 10)
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }

	    // Get the offset of the new holiday to be added.
	    short position = (short)(3 + 2 * 5 + 2 * 5);
	    
	    // Set the new data of the patient.
        patientData[position]   		   = newStartDay;
        patientData[(short)(position + 1)] = newStartMonth;
        patientData[(short)(position + 2)] = newStartYear;
        patientData[(short)(position + 3)] = newEndDay;
        patientData[(short)(position + 4)] = newEndMonth;
        patientData[(short)(position + 4)] = newEndYear;
    }
    
    
    private byte getDaysInMonth (byte month, byte year)
    {
        switch (month)
        {
            case  1:
            case  3:
            case  5:
            case  7:
            case  8:
            case 10:
            case 12:
            	return 31;
            case  4:
            case  6:
            case  9:
            case 11:
            	return 30;
            case 2:
                int y = (year & 0xFF) + 2000;
                boolean leap = ((y % 4) == 0 && (y % 100) != 0) || (y % 400) == 0;
                return (byte)(leap ? 29 : 28);
            default:
                return 30;
        }
    }
}