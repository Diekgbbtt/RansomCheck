package com.sample;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.utilities.Toolbox;
import com.utilities.Toolbox.databaseType;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.naming.spi.DirStateFactory.Result;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.delphix.masking.api.plugin.MaskingAlgorithm;
import com.delphix.masking.api.plugin.exception.MaskingException;
import com.delphix.masking.api.plugin.referenceType.AlgorithmInstanceReference;
import com.delphix.masking.api.plugin.utils.GenericData;
import com.delphix.masking.api.plugin.utils.GenericDataRow;
import com.delphix.masking.api.provider.ComponentService;
import com.delphix.masking.api.provider.LogService;

import com.utilities.WhereCondition;

import javapasswordsdk.*;
import javapasswordsdk.exceptions.*;



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
	@JsonProperty("CArk_AppID")
	public String carkAppId;
	@JsonProperty("CArk_Safe")
	public String carkSafe;

	private LogService logger;
	private Toolbox toolbox;
	private Connection connection;
	
	//database id, table id e column id, result
	@Override
    public void setup(@Nonnull ComponentService serviceProvider)  {
		logger = serviceProvider.getLogService();
		toolbox = new Toolbox();
	}
	
 
	@Override
	public GenericDataRow mask(@Nullable GenericDataRow genericData) throws MaskingException {

		try {
        	
        	// reading the column values
    		GenericData databaseId = genericData.get("DATABASE_ID");
    		GenericData tableId = genericData.get("TABLE_ID");
			GenericData columnId = genericData.get("COLUMN_ID");
    		GenericData res = genericData.get("RESULT");
    		GenericData currentDate = genericData.get("TIMESTAMP");

    		String db = databaseId.getStringValue();
    		String table = tableId.getStringValue();
			String col = columnId.getStringValue();
			ArrayList<String> values_list = new ArrayList<String>();
			WhereCondition condizione = new WhereCondition(values_list);
    		connection = toolbox.prepareDBConnection(databaseType.valueOf(db_dbType),db_hostname,db_port,db_instance,db_addParams,db_username,db_password );
    		ResultSet rs = toolbox.executeQuery(connection, "SELECT TECHNOLOGY, HOSTNAME, PORT, COALESCE(SID, SERVICE, LOCATOR), DB_SCHEMA, TABLE_NAME, COLUMN_NAME, USERNAME, PASSWORD FROM "+db_schema+".CHECK_VIEW_2 WHERE DB_ID = '" + db + "' AND TABLE_ID = '" + table + "' AND COLUMN_ID = '" + col +"'");

    		boolean check = false;
    		String tecnologia = "";
    		String host = "";
    		String port = "";
    		String sid_service = "";
    		String schema = "";
    		String tableName = "";
    		String columnName = "";
    		// String legalEntity = "";
    		// String objectName = "";
    		String username = "";
    		String password = "";
    		
    		if(rs != null) {
					while(rs.next()) {
    					tecnologia = rs.getString(1).split(" ")[0];
    		    		host = rs.getString(2);
    		    		port = rs.getString(3);
    		    		sid_service = rs.getString(4);
    		    		schema = rs.getString(5);
    		    		tableName = rs.getString(6);
    		    		columnName = rs.getString(7);
    		    		// legalEntity = rs.getString(9);
    		    		// objectName = rs.getString(10);
    		    		username = rs.getString(8);
    		    		password = rs.getString(9);
    		    		check = true;
					}
    			}
    		rs.close();

		if(check) {
				String checkQuery = "SELECT ";
				ResultSet values_rs = toolbox.executeQuery(connection, 
											"SELECT DISTINCT VALUE FROM "+db_schema+".CHECK_BASE WHERE ID = ANY (SELECT DISTINCT ID_BASE FROM "+db_schema+".CHECK_LINK WHERE ID_CHECK = (SELECT DISTINCT ID FROM "+db_schema+".CHECK_2 WHERE DATABASE_ID = '"+db+"' AND TABLE_ID = '"+table+"' AND COLUMN_ID = '"+col+"'))");
			if(values_rs != null) {
				while(values_rs.next()) {
					values_list.add(values_rs.getString(1));
				}
				condizione.setValues(values_list);
				condizione.setCol(columnName);
				values_rs.close();

				checkQuery += condizione.getWhere();
				checkQuery = checkQuery.substring(0, checkQuery.length() - 7);
				checkQuery += " AS "+columnName+"";
				}
			
			if(!checkQuery.equals(" AS "+columnName+"")) {
				String additionalParams = null;
				String pwd = password;
				if(tecnologia.equals("DB2")) {
					additionalParams = ":securityMechanism=9;encryptionAlgorithm=2;defaultIsolationLevel=1;";
				}
				
				Connection connessione = toolbox.prepareDBConnection(databaseType.valueOf(tecnologia), host, port, sid_service, additionalParams, username, pwd);
				
				logger.info(checkQuery + " FROM " + schema + ".\"" + tableName + "\"");
				
				ResultSet risultato = toolbox.executeQuery(connessione, checkQuery + " FROM " + schema + ".\"" + tableName + "\"");

				JSONObject totalResult = new JSONObject();
				HashMap<String, String> val = new HashMap<String, String>();

				if(risultato != null) {
					while(risultato.next()) {
						String results = risultato.getString(1);
						if(results.split(":;", -1).length-1 != 2 && // check verifica bug in scrittura (?)
							results.split(":0", -1).length-1 != condizione.getValues().size()) { // check verfiica almeno un match
							String types[] = results.split(";");
							for (String t:types) {
								String values[] = t.split(":");
								if(!values[1].equals("0"))
									val.put(values[0], values[1]);
							}
						}
					}
					totalResult.putAll(val);
					risultato.close();

				} else {
					totalResult.put("No matching values found", null);
					}

				if(!(totalResult.isEmpty())) {
					res.setValue(ByteBuffer.wrap(totalResult.toJSONString().getBytes(StandardCharsets.UTF_8)));
					currentDate.setValue(LocalDateTime.now());
					connessione.close();
				} else { System.err.println("No value found in the table"); }

				connection.close();
			} else {
				System.out.println("No values found in with following parameters : \n db_id : " + db + "\n tb_id : " + table + " \n col_id : " + col + " ");
			}

		} else {
				System.out.println("No column found in the view check_view_2 with following parameters : \n db_id : " + db + "\n tb_id : " + table + " \n col_id : " + col + " ");
			}
				
		} catch (Exception e) {
        	StringWriter sw = new StringWriter();
        	e.printStackTrace(new PrintWriter(sw));
			// logger.info(sw.toString());
        	throw new MaskingException(sw.toString() + " with following parameters : \n db_id : " + genericData.get("DATABASE_ID").getStringValue() + "\n tb_id : " + genericData.get("TABLE_ID").getStringValue() + " \n col_id : " + genericData.get("COLUMN_ID").getStringValue() + " \n\n With following values : \n  ");
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
