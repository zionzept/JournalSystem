package client;

import data.Journal;

public class displayTest {

	public static void main(String[] args) {
		Journal journal = new Journal("patient", "doctor", "nurse", "division", "data");
		GUICreatorThread t = new GUICreatorThread(journal, true);
		t.start();
		try {
			t.join();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(journal.getData());

	}

}
