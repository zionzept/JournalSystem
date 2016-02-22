package data;

public class Journal {
	private String patient;
	private String doctor;
	private String nurse;
	private String division;
	private String data;

	/**
	 * Create a new Journal.
	 */
	public Journal(String patient, String doctor, String nurse, String division, String data) {
		this.patient = patient.toLowerCase();
		this.doctor = doctor.toLowerCase();
		this.nurse = nurse.toLowerCase();
		this.division = division.toLowerCase();
		this.data = data.toLowerCase();
	}
	/**
	 * Create a new Journal without a nurse.
	 */
	public Journal(String patient, String doctor, String division, String data) {
		this(patient, doctor, null, division, data);
	}

	public void setPatient(String patient) {
		this.patient = patient;
	}

	public void setDoctor(String doctor) {
		this.doctor = doctor;
	}

	public void setNurse(String nurse) {
		this.nurse = nurse;
	}

	public void setDivision(String division) {
		this.division = division;
	}

	public void setData(String data) {
		this.data = data;
	}
	
	public String setPatient() {
		return patient;
	}

	public String getDoctor() {
		return doctor;
	}

	public String getNurse() {
		return nurse;
	}

	public String getDivision() {
		return division;
	}

	public String getData() {
		return data;
	}
	
	public String getPatient(){
		return patient;
	}
	
	public String toString(){
		return "Journal for " + patient + ".";
		
	}
}
