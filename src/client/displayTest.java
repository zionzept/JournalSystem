package client;

import data.Journal;

public class displayTest {

	public static void main(String[] args) {
		Journal journal = new Journal("patient", "doctor", "nurse", "division", "data");
		JournalDisplay disp = new JournalDisplay(journal, true);

	}

}
