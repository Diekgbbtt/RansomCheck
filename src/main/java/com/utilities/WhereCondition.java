package com.utilities;

import java.util.ArrayList;

public class WhereCondition {

	private ArrayList<String> values;
	private String column;
	
	public WhereCondition(ArrayList<String> values) {
		this.values = values;
	}
		
	public WhereCondition(ArrayList<String> values, String column) {
		super();
		this.values = values;
		this.column = column;
	}
	public String getCol() {
		return column;
	}
	public void setCol(String col) {
		this.column = col;
	}
	public ArrayList<String> getValues() {
		return values;
	}
	public String getValue(int index) {
		return values.get(index);
	}
	public void setValues(ArrayList<String> value) {
		this.values = value;
	}

	public String getWhereBindvar() {
		String where = "";
		for (int i = 0; i < values.size(); i++) {
			if(where.equals(""))
				where += "SELECT ";
			where += " '?' || sum(case when(TRIM(UPPER(?)) = '?' ) then 1 else 0 end) ||';'||";
		}
		if(!where.equals(""))
			where = where.substring(0, where.length()-7);
			where += " AS "+this.getCol()+"";
	return where;
	}
	
	public String getWhere() {
		String where = "";
		for (String val : values) {
			if(where.equals(""))
				where += "SELECT ";
			where += " '"+val+":' || sum(case when(TRIM(UPPER("+this.getCol()+")) = '"+val.toUpperCase().trim()+"'";
			where += ") then 1 else 0 end) ||';'||";
		}
		if(!where.equals(""))
			where = where.substring(0, where.length()-7);
			where += " AS "+this.getCol()+"";
		return where;
	}

	
}
