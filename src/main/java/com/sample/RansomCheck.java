package com.sample;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.json.simple.JSONObject;

import com.delphix.masking.api.plugin.MaskingAlgorithm;
import com.delphix.masking.api.plugin.exception.MaskingException;
import com.delphix.masking.api.plugin.utils.GenericDataRow;
import com.delphix.masking.api.provider.ComponentService;
import com.delphix.masking.api.provider.LogService;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.utilities.InvalidIndexParametersException;
import com.utilities.TableDetails;
import com.utilities.Toolbox;
import com.utilities.Toolbox.databaseType;
import com.utilities.WhereCondition;



public class RansomCheck implements MaskingAlgorithm<GenericDataRow> {
	
	@Override
    public boolean getAllowFurtherInstances() {
        return true;
    }
	
	@JsonProperty("db_dbType")
	public String db_dbType;
	@JsonProperty("db_hostname")
	public String db_hostname;
	@JsonProperty("db_port")
	public String db_port;
	@JsonProperty("db_username")
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
		this.condition = null;
		this.values_list = new ArrayList<>();
		this.checkQuery = "";
		this.valuesClustersResultSet = null;
		this.retrievedValuesClusters = new JSONObject();
	}
	
	// object to hold resutls table details
	private void getResultRowData(GenericDataRow genericData) {
		this.resultRowData.setDetails(
			genericData.get("DATABASE_ID").getStringValue(),
			genericData.get("TABLE_ID").getStringValue(),
			genericData.get("COLUMN_ID").getStringValue(),
			genericData.get("RESULT"),
			genericData.get("TIMESTAMP")
		);
	}
	
	// object to hold target table details, including all parameters required to connect to the target table
	private void getTargetTableData() throws SQLException, ClassNotFoundException, IllegalArgumentException, InvalidIndexParametersException{
		try{
			this.containerConnection = toolbox.prepareDBConnection(databaseType.valueOf(db_dbType),db_hostname,db_port,db_instance,db_addParams,db_username,db_password );
			ResultSet rs = toolbox.executeQuery(this.containerConnection, "SELECT TECHNOLOGY, HOSTNAME, PORT, COALESCE(SID, SERVICE, LOCATOR), DB_SCHEMA, TABLE_NAME, COLUMN_NAME, USERNAME, PASSWORD FROM ?.CHECK_VIEW_2 WHERE DB_ID = '?' AND TABLE_ID = '?' AND COLUMN_ID = '?'", db_schema, resultRowData.getDb(), resultRowData.getTable(), resultRowData.getCol());
			if(rs != null && rs.next()) {
				this.targetTableData.setDetails(
				rs.getString(1).split(" ")[0],
				rs.getString(2),
				rs.getString(3),
				rs.getString(4),
				rs.getString(5),
				rs.getString(6),
				rs.getString(7),
				rs.getString(8),
				rs.getString(9)
				); 
				rs.close();
			} else { 
				this.logger.info("No table/column found in the general database view with these parameters\n db_id : " + resultRowData.getDb() + "\n tb_id : "+ resultRowData.getTable() +"\n col_id : "+ resultRowData.getCol());
				throw new InvalidIndexParametersException("No table/column found in the general database view with these parameters", resultRowData.getDb(), resultRowData.getTable(), resultRowData.getCol()); 
			}
		} catch(SQLException e){
				throw new SQLException(e.getMessage() + "\n Error connecting to or querying the general database view");
		}
	}
	// get exepected values for the current checked column by the masking algorithm
	private void getColumnExpectedValues() throws SQLException, ClassNotFoundException, InvalidIndexParametersException{
		ResultSet values_rs = toolbox.executeQuery(this.containerConnection, 
								"SELECT DISTINCT VALUE FROM ?.CHECK_BASE WHERE ID_CHECK = (SELECT DISTINCT ID FROM ?.CHECK_2 WHERE DATABASE_ID = '?' AND TABLE_ID = '?' AND COLUMN_ID = '?'))", db_schema, db_schema, db_schema, resultRowData.getDb(), resultRowData.getTable(), resultRowData.getCol());
		if(values_rs != null) { 
			while(values_rs.next()) {
				values_list.add(values_rs.getString(1));
			}
			values_rs.close();
			toolbox.closeConnection(this.containerConnection);
		} else {
			this.logger.info("No expected values found in expected values table(CHECK_BASE) with these parameters\n db_id : " + resultRowData.getDb() + "\n tb_id : "+ resultRowData.getTable() +"\n col_id : "+ resultRowData.getCol());
			throw new InvalidIndexParametersException("No expected values found in expected values table(CHECK_BASE) with these parameters", resultRowData.getDb(), resultRowData.getTable(), resultRowData.getCol()); 
		}
	}

	// buld the fundamental dynamic part of the final query, the confront between expected and effective values inserted dinamically 
	private void buildClusteringQuery() throws SQLException, ClassNotFoundException, InvalidIndexParametersException {
		if(values_list.size() > 1) { // redundant values list retrieve for safety
			condition.setValues(values_list);
		} else { 
			this.logger.info("No expected values found in expected values table(CHECK_BASE) with the following parameters \n db_id : " + resultRowData.getDb() + "\n tb_id : "+ resultRowData.getTable() +"\n col_id : "+ resultRowData.getCol());
			throw new InvalidIndexParametersException("No expected values found in expected values table(CHECK_BASE) with the following parameters", resultRowData.getDb(), resultRowData.getTable(), resultRowData.getCol()); 
		}
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
			this.valuesClustersResultSet = toolbox.executeQuery(this.targetTableConnection, checkQuery, targetTableData.getSchema(), targetTableData.getTable());
	}

	@SuppressWarnings("unchecked")
	private void parseEffectiveValues() throws SQLException {
		HashMap<String, String> values = new HashMap<>();
		if(this.valuesClustersResultSet != null) {
			while(this.valuesClustersResultSet.next()) {
				if(this.valuesClustersResultSet.getString(1).split(":;", -1).length-1 != 2 && // check verifica bug in scrittura (?)
				this.valuesClustersResultSet.getString(1).split(":0", -1).length-1 != condition.getValues().size()) { // check verfiica almeno un match
					for (String t:this.valuesClustersResultSet.getString(1).split(";")) {
						if(!t.split(":")[1].equals("0"))
						values.put(t.split(":")[0], t.split(":")[1]);
					}
				} else {
					this.valuesClustersResultSet.close();
					toolbox.closeConnection(this.targetTableConnection);
					this.logger.info("neither one match found or ':;' bug occurred in results writing, raise problem to support");
					writeEffectiveValues("neither one match found or ':;' bug occurred in results writing, raise problem to support");
				}
			}
			retrievedValuesClusters.putAll(values);
			this.valuesClustersResultSet.close();
			toolbox.closeConnection(this.targetTableConnection);
			writeEffectiveValues();

		} else {
			this.valuesClustersResultSet.close();
			this.logger.info("error in query to retrieve effective values execution");
			writeEffectiveValues("error in query to retrieve effective values execution");
		}
	}

	// write good scenario, results are written 
	private void writeEffectiveValues() {
			this.resultRowData.getResult().setValue(ByteBuffer.wrap(retrievedValuesClusters.toJSONString().getBytes(StandardCharsets.UTF_8)));
			this.resultRowData.getTimestamp().setValue(LocalDateTime.now());
	}

	// faulty scenario, desciption of the error is written
	private void writeEffectiveValues(String errorString) {
			this.resultRowData.getResult().setValue(ByteBuffer.wrap(errorString.getBytes(StandardCharsets.UTF_8)));
			this.resultRowData.getTimestamp().setValue(LocalDateTime.now());
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
			if (e instanceof InvalidIndexParametersException) {
			 	writeEffectiveValues(((InvalidIndexParametersException) e).printMessageWithIndexes());
				return genericData;
			} else if(e instanceof IllegalArgumentException) {
				writeEffectiveValues(((IllegalArgumentException) e).getMessage());
				return genericData;
			} else {
				StringWriter sw = new StringWriter();
				e.printStackTrace(new PrintWriter(sw));
				throw new MaskingException(sw.toString() +  "\n Exception message : \n" + e.getMessage() + " \n With following parameters : \n db_id : " + resultRowData.getDb() + "\n tb_id : " + resultRowData.getTable() + " \n col_id : " + resultRowData.getCol() + " \n\n With following values : \n " + String.join(",  ", values_list));
			}
		}
		return genericData;
	}
	@Override
	public Map<String, MaskingType> listMaskedFields() {
        Map<String, MaskingType> maskedFields = new HashMap<> ();
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