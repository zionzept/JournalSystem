package client;

import data.Journal;

public class GUICreatorThread extends Thread{
	
	private Journal journal;
	private boolean editable;
	
	public GUICreatorThread(Journal journal, boolean editable){
		this.journal = journal;
		this.editable = editable;
	}
	
	public void run(){
		JournalDisplay disp = new JournalDisplay(journal, editable);
		disp.waitForDone();
	}
}