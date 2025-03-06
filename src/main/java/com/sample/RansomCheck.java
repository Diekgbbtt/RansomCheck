package com.sample;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.utilities.TableDetails;
import com.utilities.Toolbox;
import com.utilities.Toolbox.databaseType;
import com.utilities.WhereCondition;


import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.json.simple.JSONObject;

import javapasswordsdk.*;
import javapasswordsdk.exceptions.*;

import com.delphix.masking.api.plugin.MaskingAlgorithm;
import com.delphix.masking.api.plugin.exception.MaskingException;
import com.delphix.masking.api.plugin.referenceType.AlgorithmInstanceReference;
import com.delphix.masking.api.plugin.utils.GenericData;
import com.delphix.masking.api.plugin.utils.GenericDataRow;
import com.delphix.masking.api.provider.ComponentService;
import com.delphix.masking.api.provider.LogService;



public class RansomCheck implements MaskingAlgorithm<GenericDataRow> {
	
	@Override
    public boolean getAllowFurtherInstances() {
        return true;
    }
	
	@JsonProperty("db_dbType") // ORACLE
	public String db_dbType;
	@JsonProperty("db_hostname")
	public String db_hostname;
	@JsonProperty("db_port")
	public String db_port;
	@JsonProperty("db_username") // DELPHIXDEV
	public String db_username;
	@JsonProperty("db_schema")
	public String db_schema;
	@JsonProperty("db_password")
	public String db_password;
	@JsonProperty("db_instance")
	public String db_instance;				
	@JsonProperty("db_addParams")
	public String db_addParams;

	// instantiate required objects - when masking algo will be instantiated by the  masking plugins interface these objects will be instantiated by java deafult no-args constructor for all classes, inherited from Object class
	private LogService logger;
	private Toolbox toolbox;
	private Connection containerConnection;
	private Connection targetTableConnection;
	private ArrayList<String> values_list;
	private WhereCondition condition;
	private TableDetails resultRowData;
	private TableDetails targetTableData;
	private String checkQuery;
	private ResultSet valuesClustersResultSet;
	private JSONObject retrievedValuesClusters;
	
	//initialize required objects for the masking process 
	@Override
    public void setup(@Nonnull ComponentService serviceProvider)  {
		this.logger = serviceProvider.getLogService();
		this.toolbox = new Toolbox();
		this.condition = new WhereCondition(values_list);
		this.values_list = new ArrayList<String>();
		this.checkQuery = "";
		this.valuesClustersResultSet = null;
		this.retrievedValuesClusters = new JSONObject();
	}
	
	// object to hold resutls table details
	private void getResultRowData(GenericDataRow genericData) {
		this.resultRowData = new TableDetails(
			genericData.get("DATABASE_ID").getStringValue(),
			genericData.get("TABLE_ID").getStringValue(),
			genericData.get("COLUMN_ID").getStringValue(),
			genericData.get("RESULT"),
			genericData.get("TIMESTAMP")
		);
	}
	
	// object to hold target table details, including all parameters required to connect to the target table
	private void getTargetTableData() throws SQLException, ClassNotFoundException {
		this.containerConnection = toolbox.prepareDBConnection(databaseType.valueOf(db_dbType),db_hostname,db_port,db_instance,db_addParams,db_username,db_password );
		ResultSet rs = toolbox.executeQuery(this.containerConnection, "SELECT TECHNOLOGY, HOSTNAME, PORT, COALESCE(SID, SERVICE, LOCATOR), DB_SCHEMA, TABLE_NAME, COLUMN_NAME, USERNAME, PASSWORD FROM ?.CHECK_VIEW_2 WHERE DB_ID = '?' AND TABLE_ID = '?' AND COLUMN_ID = '?'", db_schema, resultRowData.getDb(), resultRowData.getTable(), resultRowData.getCol());
		if(rs != null && rs.next()) {
			this.targetTableData = TableDetails(
			rs.getString(1).split(" ")[0],
			rs.getString(2),
			rs.getString(3),
			rs.getString(4),
			rs.getString(5),
			rs.getString(6),
			rs.getString(7),
			rs.getString(8),
			rs.getString(9)
			); rs.close();
		} else { logger.info("No table found in the general database view with following parameters : \n db_id : " + resultRowData.getDb() + "\n tb_id : " + resultRowData.getTable() + " \n col_id : " + resultRowData.getCol()); }
	}
	// get exepected values for the current checked column by the masking algorithm
	private void getColumnExpectedValues() throws SQLException, ClassNotFoundException {
		ResultSet values_rs = toolbox.executeQuery(this.containerConnection, 
								"SELECT DISTINCT VALUE FROM ?.CHECK_BASE WHERE ID_CHECK = (SELECT DISTINCT ID FROM ?.CHECK_2 WHERE DATABASE_ID = '?' AND TABLE_ID = '?' AND COLUMN_ID = '?'))", db_schema, db_schema, db_schema, resultRowData.getDb(), resultRowData.getTable(), resultRowData.getCol());
		if(values_rs != null) { 
			while(values_rs.next()) {
				values_list.add(values_rs.getString(1));
			}
			values_rs.close();
			this.containerConnection.close();
		} else { logger.info("No expected values found in expected values table(CHECK_BASE) with the following parameters : \n db_id : " + resultRowData.getDb() + "\n tb_id : " + resultRowData.getTable() + " \n col_id : " + resultRowData.getCol()); }

	}

	// buld the fundamental dynamic part of the final query, the confront between expected and effective values inserted dinamically 
	private void buildClusteringQuery() throws SQLException, ClassNotFoundException {
		if(values_list.size() > 1) { // redundant values list retrieve for safety
			condition.setValues(values_list);
		} else { logger.info("No expected values found in expected values table(CHECK_BASE) with the following parameters : \n db_id : " + resultRowData.getDb() + "\n tb_id : " + resultRowData.getTable() + " \n col_id : " + resultRowData.getCol() + ", before building the where condition, raise problem to support"); }
		condition.setCol(targetTableData.getCol());
		checkQuery += condition.getWhere();
	}

	private void extractColumnEffectiveValuesClusters() throws ClassNotFoundException, SQLException {
			if(targetTableData.getTech().equals("DB2")) {
				db_addParams = ":securityMechanism=9;encryptionAlgorithm=2;defaultIsolationLevel=1;";
			}
			this.targetTableConnection = toolbox.prepareDBConnection(databaseType.valueOf(targetTableData.getTech()), targetTableData.getHost(), targetTableData.getPort(), targetTableData.getSid(), db_addParams, targetTableData.getUsr(), targetTableData.getPwd());
			this.logger.info(checkQuery + " FROM " + targetTableData.getSchema() + ".\"" + targetTableData.getTable() + "\""); // log query for debugging
			this.checkQuery += " FROM ?.\"?\""; // schema and tablename added later
			PreparedStatement query = toolbox.prepareStatament(this.targetTableConnection, checkQuery, condition, targetTableData.getSchema(), targetTableData.getTable());
			this.valuesClustersResultSet = query.executeQuery();
	}

	private void parseEffectiveValues() throws Exception {

		HashMap<String, String> values = new HashMap<String, String>();
		if(this.valuesClustersResultSet != null) {
			while(this.valuesClustersResultSet.next()) {
				if(this.valuesClustersResultSet.getString(1).split(":;", -1).length-1 != 2 && // check verifica bug in scrittura (?)
				this.valuesClustersResultSet.getString(1).split(":0", -1).length-1 != condition.getValues().size()) { // check verfiica almeno un match
					for (String t:this.valuesClustersResultSet.getString(1).split(";")) {
						if(!t.split(":")[1].equals("0"))
						values.put(t.split(":")[0], t.split(":")[1]);
					}
				} else {
					this.logger.info("neither one match found or ':;' bug occurred in results writing, raise problem to support");
					writeEffectiveValues(Optional.of("neither one match found or ':;' bug occurred in results writing, raise problem to support"));
				}
			}
			retrievedValuesClusters.putAll(values);
			this.valuesClustersResultSet.close();
			writeEffectiveValues(Optional.empty());

		} else {
			this.logger.info("error in query to retrieve effective values execution");
			writeEffectiveValues(Optional.of("error in query to retrieve effective values execution"));
		}

	}

	private void writeEffectiveValues(Optional<String> errorString) throws Exception {
		if(!(retrievedValuesClusters.isEmpty())) { // if 
			this.resultRowData.getResult().setValue(ByteBuffer.wrap(retrievedValuesClusters.toJSONString().getBytes(StandardCharsets.UTF_8)));
		} else {
			String errorMessage = errorString.orElse("undefined error");
			this.resultRowData.getResult().setValue(ByteBuffer.wrap(errorMessage.getBytes(StandardCharsets.UTF_8)));
		}
		this.resultRowData.getTimestamp().setValue(LocalDateTime.now());
		this.targetTableConnection.close(); // close connection to target table
	}

	@Override
	public GenericDataRow mask(@Nullable GenericDataRow genericData) throws MaskingException {
		try {
			getResultRowData(genericData);
			getTargetTableData();
			getColumnExpectedValues();
			buildClusteringQuery();
			extractColumnEffectiveValuesClusters();
			parseEffectiveValues();
		} catch (Exception e) {
        	StringWriter sw = new StringWriter();
        	e.printStackTrace(new PrintWriter(sw));
        	throw new MaskingException(sw.toString() + " with following parameters : \n db_id : " + resultRowData.getDb() + "\n tb_id : " + resultRowData.getTable() + " \n col_id : " + resultRowData.getCol() + " \n\n With following values : \n " + String.join(",  ", values_list));
        }
		return genericData;
	}
	
	@Override
	public Map<String, MaskingType> listMaskedFields() {
        Map<String, MaskingType> maskedFields = new HashMap<String, MaskingType> ();
        maskedFields.put("DATABASE_ID", MaskingType.STRING);
        maskedFields.put("TABLE_ID", MaskingType.STRING);
		maskedFields.put("COLUMN_ID", MaskingType.STRING);
        maskedFields.put("RESULT", MaskingType.BYTE_BUFFER);
        maskedFields.put("TIMESTAMP", MaskingType.LOCAL_DATE_TIME);
		
        return maskedFields;
    }
	
	@Override
	public String getName() {
		return "RansomCheck";
	}


}
