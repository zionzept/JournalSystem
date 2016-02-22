package server;

import java.util.HashMap;

public class Subject {
	HashMap<String, String> properties;

	public Subject(String subjectName) {
		this.properties = new HashMap<>();
		String[] properties = subjectName.split(", ");
		for (String property : properties) {
			setProperty(property);
		}
	}
	
	private void setProperty(String property) {
		String[] kv = property.split("=");
		properties.put(kv[0], kv[1]);
	}
	
	public String getProperty(String key) {
		return properties.get(key).toLowerCase();
	}
}
