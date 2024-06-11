package com.utilities;

import java.util.ArrayList;

public class WhereCondition {


	// private String type;
	private ArrayList<String> values;
	private String column;
	private String colId;
	
	public WhereCondition(ArrayList<String> values) {
		this.values = values;
	}
		
	public WhereCondition(String type, ArrayList<String> values, String column) {
		super();
		// this.type = type;
		this.values = values;
	}

	public String getCol() {
		return column;
	}
	public void setCol(String col) {
		this.column = col;
	}
	public String getColId() {
		return colId;
	}
	public void setColId(String col_id) {
		this.colId = col_id;
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
//	public String getColumn() {
//		return column;
//	}
//	public void setColumn(String column) {
//		this.column = column;
//	}
	
	public String getWhere() {
		String where = "";
		for (String val : values) {
			
			where += " '"+val+":' || sum(case when(TRIM( UPPER("+this.getCol()+")) = '"+val.toUpperCase()+"'";
			where += ") then 1 else 0 end) ||';'||";
		}
		// where = where.substring(0,where.length() - 3);
		return where;

		// LIKE keyword per cercare pattern in una colonna,
		// in questo caso cerca nel nome della colonna(?) la stringa in val
		// preceduta o seguita da qualsiasi altro carattere

		// sum(case when( 
		//		UPPER(" + col + ") LIKE '%" + val + "%' OR
		//		UPPER(" + col + ") LIKE '%" + val + "%' OR
		// 		....
		//		..
		//		.
		//		) then 1 else 0 end)
		//

		/* non mi è chiara la stringa
		* per ciascun valore in values(fetchato tramite query in RansomCheck) alla stringa where viene 
		* aggiunta " UPPER(" + col + ") LIKE '%" + val + "%' OR" , quindi abbiamo un costrutto 
		* switch case con un solo caso che riporta più possibli espressioni e che viene risolto ad una espressione
		* in base al valore di col, se un confronto viene risolto con successo ritorna uno altrimenti zero
		* "sum" è usata per avere solo il valore numerico(1 o 0). Non caspisco il sesno della keyword case
		*
		 */
		
//		return "WHERE UPPER(" + this.column + ") NOT LIKE '" + valore +"%'";
	}

	
}
