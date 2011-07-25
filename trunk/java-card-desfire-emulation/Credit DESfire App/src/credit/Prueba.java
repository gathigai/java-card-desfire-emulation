package credit;

import java.util.List;
import javax.smartcardio.*;
import java.security.NoSuchAlgorithmException;


import be.fedict.util.TextUtils;

import be.fedict.eidtoolset.exceptions.AIDNotFound;
import be.fedict.eidtoolset.exceptions.InvalidResponse;
import be.fedict.eidtoolset.exceptions.NoCardConnected;
import be.fedict.eidtoolset.exceptions.NoReadersAvailable;
import be.fedict.eidtoolset.interfaces.SmartCardReaderCommandsInterface;
import be.fedict.eidtoolset.interfaces.SmartCardReaderInterface;


public class Prueba {

	/**
	 * @param args
	 */
	
	
	
    private List readers;
    private CardTerminal reader;
    private Card card;
    private CardChannel conn;
    private int usingReaderNr = -1;
    private String myName = "";
    /**
	 * debugLevel = 0: no debug information; 1: minimal debug information
	 * (reader and card information); 2: maximal debug information (apdus)
	 */
	private int debugLevel = 2;




public String[] getReaders() throws NoReadersAvailable, NoSuchAlgorithmException, CardException {
            List allReaders;
            allReaders = TerminalFactory.getInstance("PC/SC", null).terminals().list();
            if (allReaders.isEmpty()) {
                    throw new NoReadersAvailable();
            }
            String[] names = new String[allReaders.size()];
            for (int i = 0; i < allReaders.size(); i++)
                    names[i] = ((CardTerminal) allReaders.get(i)).getName();
            return names;
    }




    public void lookForSmartCard(String preferredReader, int milliSecondsBeforeTryingAnotherReader, byte[] AID_APDU) throws NoReadersAvailable, CardException, NoSuchAlgorithmException, AIDNotFound, NoCardConnected {
            readers = TerminalFactory.getInstance("PC/SC", null).terminals().list();
            if (readers.isEmpty()) {
                    throw new NoReadersAvailable();
            }
            if (debugLevel > 0) {
                    for (int i = 0; i < readers.size(); i++)
                            System.err.println("Discovered smart card reader <" + ((CardTerminal) readers.get(i)).getName() + "> as reader <" + i + ">");
            }
            usingReaderNr = 0;
            preferredReader = preferredReader.toUpperCase();
            for (int i = 0; i < readers.size(); i++)
            	
                    if (((CardTerminal) readers.get(i)).getName().toUpperCase().indexOf(preferredReader) >= 0)
                            usingReaderNr = i;
            System.out.println("Name "+ ((CardTerminal) readers.get(usingReaderNr)).getName().toUpperCase());
            if (debugLevel > 0)
                    System.err.println("Using smart card reader <" + usingReaderNr + ">, <" + ((CardTerminal) readers.get(usingReaderNr)).getName() + ">, preferred reader was <" + preferredReader + ">");
            card = null;
            //do {
                    if (debugLevel > 0)
                            System.err.println("Waiting for a card to be inserted into smart card reader <" + usingReaderNr + ">, <" + ((CardTerminal) readers.get(usingReaderNr)).getName() + ">, will timeout in <" + milliSecondsBeforeTryingAnotherReader
                                            + "> milliseconds");
                    reader = (CardTerminal) readers.get(usingReaderNr);
                    if (reader.isCardPresent() || reader.waitForCardPresent(milliSecondsBeforeTryingAnotherReader)) {
                            // Always connect using T=0
                            try {
                                    card = reader.connect("T=0");
                            } catch (CardException e) {
                                    // Sometimes the NFC phones only support "T=1" to get
                                    // connection (nothing else changes though)
                                    card = reader.connect("T=1");
                            }
                            conn = card.getBasicChannel();
//                           selectApplet(AID_APDU); //Aquí teniamos un problema ya que no existía tal Aplicacion
                    } else
                            card = null;
              /*      if (card == null) {
                            usingReaderNr++;
                            if (usingReaderNr >= readers.size())
                                    throw new NoCardConnected();
                            if (debugLevel > 0)
                                    System.err.println("Trying again with smart card reader <" + usingReaderNr + ">, <" + ((CardTerminal) readers.get(usingReaderNr)).getName() + "> as no card was detected within <" + milliSecondsBeforeTryingAnotherReader
                                                    + "> milliseconds");
                    }*/
                    if (card == null) {
                    	throw new NoCardConnected();
                    }
            //} while (card == null);
            if (debugLevel > 0)
                    System.err.println("Discovered card in <" + ((CardTerminal) readers.get(usingReaderNr)).getName() + ">");
            if (debugLevel > 0)
                    System.err.println("Card ATR is <" + TextUtils.hexDump(card.getATR().getBytes()) + ">");
            myName = ((CardTerminal) readers.get(usingReaderNr)).getName();
    }




    private void selectApplet(byte[] AID_APDU) throws AIDNotFound, CardException {
            ResponseAPDU response = conn.transmit(new CommandAPDU(AID_APDU));
            if (response.getSW() != (Integer) 0x9000)
                    throw new AIDNotFound();
    }



public byte[] sendCommand(byte[] command) throws InvalidResponse, NoCardConnected, CardException {
            if (card == null) {
                    throw new NoCardConnected();
            }
            if (debugLevel > 1)
                    System.err.println("Sending <" + TextUtils.hexDump(command) + "> to card in reader <" + ((CardTerminal) readers.get(usingReaderNr)).getName() + ">");
            ResponseAPDU response = conn.transmit(new CommandAPDU(command));
            if (debugLevel > 1)
                    System.err.println("Receiving data <" + TextUtils.hexDump(response.getBytes()) + ">");
            return response.getBytes();
    }




    public byte[] getATR() {
            return card.getATR().getBytes();
    }




    public void powerOff() throws CardException {
            try {
                    card.disconnect(true);// boolean true will reset card: a select
                    // command is needed again after this
                    card = null;
                    conn = null;
            } catch (CardException e) {
                    if (debugLevel > 0) {
                            e.printStackTrace();
                            System.err.println("Try to disconnect card form reader: " + ((CardTerminal) readers.get(usingReaderNr)).getName() + "\n Card already disconnected.");
                    }
                    card = null;
                    conn = null;
                    throw new CardException("Card already disconnected.");
            }
    }

}
