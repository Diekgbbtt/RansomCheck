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
import com.utilities.ResultValue;



import javapasswordsdk.*;
import javapasswordsdk.exceptions.*;



public class RansomCheck implements MaskingAlgorithm<GenericDataRow> {
	
	
	@Override
    public boolean getAllowFurtherInstances() {
        return true;
    }
	
	@JsonProperty("db_dbType")  	// ORACLE
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
	// no valore ultime 4 entry

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
		ArrayList<WhereCondition> wheres = new ArrayList<WhereCondition>();
		try {
        	
        	// reading the column values
    		GenericData databaseId = genericData.get("DATABASE_ID");
    		GenericData tableId = genericData.get("TABLE_ID");
			// GenericData columnId = genericData.get("COLUMN_ID");
    		GenericData res = genericData.get("RESULT");
    		GenericData currentDate = genericData.get("TIMESTAMP");

    		// casting data to string
			// quando vengono letti valori da un oggetto GenericData è encessaio castarlo
			// ad un tipo core come string
    		String db = databaseId.getStringValue();
    		String table = tableId.getStringValue();
    		connection = toolbox.prepareDBConnection(databaseType.valueOf(db_dbType),db_hostname,db_port,db_instance,db_addParams,db_username,db_password );
    		ResultSet rs = toolbox.executeQuery(connection, "SELECT TECHNOLOGY, HOSTNAME, PORT, COALESCE(SID, SERVICE, LOCATOR), DB_SCHEMA, TABLE_NAME, COLUMN_ID, COLUMN_NAME, LEGAL_ENTITY, OBJECT_NAME, USERNAME, PASSWORD FROM "+db_schema+".CHECK_VIEW WHERE DB_ID = " + db + " AND TABLE_ID = " + table);
    		
    		boolean check = false; // cosa indicherebbe?
    		String tecnologia = "";
    		String host = "";
    		String port = "";
    		String sid_service = "";
    		String schema = "";
    		String tableName = "";
    		HashMap<String, String> columnsIdName = new HashMap<String, String>();
    		String legalEntity = "";
    		String objectName = "";
    		String username = "";
    		String password = "";
    		
    		if(rs != null) {
    			while(rs.next()) {
    				if(!check) {
    					tecnologia = rs.getString(1).split(" ")[0];
    		    		host = rs.getString(2);
    		    		port = rs.getString(3);
    		    		sid_service = rs.getString(4);
    		    		schema = rs.getString(5);
    		    		tableName = rs.getString(6);
    		    		columnsIdName.put(rs.getString(7), rs.getString(8));
    		    		legalEntity = rs.getString(9);
    		    		objectName = rs.getString(10);
    		    		username = rs.getString(11);
    		    		password = rs.getString(12);
    		    		check = true;
    				}
    				else
						columnsIdName.put(rs.getString(7), rs.getString(8));
    			}
    		}
    		rs.close();
			/* nella tablla checkview sono presenti tutte le tabelle, partizionate tra diversi db, da controllare 
			 * per ogni tabella son indicate il nome delle colonne su più righe. Quindi si ripete il nome e id della
			 * tabella. Nel costrutto sopra vengono salvati i dettagli per la connessione al db e le colonne della tabella
			 * in oggetto. db id  e table id vengono passati come argomenti --> come li indico?
			*/
    		
    		if(check) {
				ResultSet checkCol_ids = toolbox.executeQuery(connection, "SELECT DISTINCT ID, COLUMN_ID  FROM "+db_schema+".CHECK_2 WHERE DATABASE_ID = '"+db+"' AND TABLE_ID = '"+table+"'");
	    		
				while(checkCol_ids.next()) {
					// String ColumnName = columnsNameId.get(checkCol_ids.getString(2));
					
					ArrayList<String> values_list = new ArrayList<String>();

					ResultSet values = toolbox.executeQuery(connection, 
											"SELECT DISTINCT VALUES FROM "+db_schema+".CHECK_BASE WHERE ID IN (SELECT DISTINCT ID_BASE FROM "+db_schema+".CHECK_LINK WHERE ID_CHECK = '"+checkCol_ids.getString(1)+"'");
					if(values!=null) {
						while(values.next()) {
							values_list.add(values.getString(1));
						}
					}
					WhereCondition condizione = new WhereCondition(values_list);
					condizione.setCol(columnsIdName.get(checkCol_ids.getString(2)));
					condizione.setColId(checkCol_ids.getString(2));
					wheres.add(condizione);
					values.close();
				}
				checkCol_ids.close();
				// abbiamo una wherecondition per ogni colonna della tabella interessata e ciscuna ha una lsita di valori da controllare
				// per la relativa colonna.
			
	    		
	    		/* if (nuovatabella != null) {	
	    			while (nuovatabella.next()){
	    				WhereCondition condizione = new WhereCondition(columns);
	    				String tipo = nuovatabella.getString(1);
	    				condizione.setType(tipo); // nome algoritmo
	    				ResultSet values = toolbox.executeQuery(connection, "SELECT DISTINCT UPPER(VALUE) FROM "+db_schema+".CHECK_ALGO WHERE LEGAL_ENTITY = '" + legalEntity  + "' AND NAME = '" + tipo + "'");
	    				// VALUE sono dei valori che devono essere ricercati, in seguito al mascheramento di una cella che ha tipo di dato
						// pari a quello nella colonna NAME ci aspettiamo uno di questi valori
						if(values != null) {
	    					ArrayList<String> valori = new ArrayList<String>();
	    					while (values.next()) {
	    						valori.add(values.getString(1));
	    					}
	    					condizione.setValues(valori);
	    					values.close();

	    				}
	    				wheres.add(condizione); 
	    			}
				*/

					/* per ciascun tipo(NAME), entry nel rs nuovatabella, viene instanziata una 
					 * WhereCondition con colonne prese da query precedente(COLUMN_NAME), colonne della tabella CHECK_VIEW
					 * tipo preso da query successiva(NAME), dalla tabella CHECK_ALGO e valori dalla query finale
					 * che vengono messi prima in una lista valori.
					 * Abbiamo una whereCondition per tipo e vengono aggiunte alla lista wheres
					 * Perchè non inizializzare anche values nella costruttore?
					 * 

	    			nuovatabella.close();
	    		}
			*/
				

				
				// columnsNameId.forEach((k,v) -> {

	    		// for(<Entry<String, String>> col: col_it) {
				String checkQuery = "SELECT ";
					for (WhereCondition where : wheres) { // inefficente, controlla le colonne anche per tutti i tipi di dati degli algortmi in check_algo
														  // quindi anche tipi di dati che i valori nelle colonne non assumono
					/* potrei fare un hashmap. Al posto della lista coloumns con i nomi di tutte le colonne, si crea un hashmap con nomecolonna->algoritmo 
					*  che gestisce tipi di dati in quella colonna. Alla vista check_view deve essere aggiunta una colonna con il nome o i nomi degli algoritmi
					* separta da virgola che gestiscono i tipi di dati in quella colonna, la query su checkview seleziona oltre al nome delle colonne anche i nomi degli algoritmi
					* in un altra colonna. Viene creato quindi l'hashMap. In seguito nella costruzione della query checkquery viene aggiunta una condizione if nel for()
					* che valuta se il tipo dell'oggetto where(nome algoritmo) è pari a uno degli algoritmi associati al nome della colonna nell'hashmap, true aggiunge
					* porzione query, FALSE non aggiunge porzione query*/
						
	    				checkQuery += ""+where.getWhere()+"";
						checkQuery = checkQuery.substring(0, checkQuery.length() - 7);
						checkQuery += " AS "+where.getColId()+",";
	    			}

				// });
				// per ciascun valore checkQuery viene incrementata di una stringa *tipo*:'||*0-1*||';'||
	    		// SELECT '*ALGO_1*:'*0/1*';'
				// SELECT 'ALGO_1:'0';''ALGO_2:'1';'...COLOUMN_NAME,  - esempio
				// questo per ciascuna colonna trovata(COLOUMN_NAME) IN CHECK_VIEW, per ciascuna tabella quando si ripete ciclo
				// query finale : SELECT 'ALGO_1:'0/1';''ALGO_2:'0/1';'...COLOUMN_NAME,'ALGO_1:'0/1';''ALGO_2:'0/1';'...COLOUMN_NAME,.....
	    		checkQuery = checkQuery.substring(0, checkQuery.length() - 1); // deve toglier ultima virgola
	    		
	    		String additionalParams = null;
//		        CYBERARK INTEGRATION
				// Create a trust manager that does not validate certificate chains
//		        TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
//		                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
//		                    return null;
//		                }
//		                public void checkClientTrusted(X509Certificate[] certs, String authType) {
//		                }
//		                public void checkServerTrusted(X509Certificate[] certs, String authType) {
//		                }
//		            }
//		        };
		 

		        
//		        // Install the all-trusting trust manager
//		        SSLContext sc = SSLContext.getInstance("SSL");
//		        sc.init(null, trustAllCerts, new java.security.SecureRandom());
//		        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
//		 
//		        // Create all-trusting host name verifier
//		        HostnameVerifier allHostsValid = new HostnameVerifier() {
//		            public boolean verify(String hostname, SSLSession session) {
//		                return true;
//		            }
//		        };
//		 
//		        // Install the all-trusting host verifier
//		        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
//		    	URL url = new URL("https://cyberarkccp.internal.unicreditgroup.eu/AIMWebService/api/Accounts?appid="+carkAppId+"&safe="+carkSafe+"&folder=Root&username="+username+"&object="+objectName+"&reason=CheckMasking");
//		    	URLConnection con = url.openConnection();
//				con.setRequestProperty("Content-Type", "application/json");
//				con.setConnectTimeout(5000);
//				con.setReadTimeout(5000);
//				BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
//				String inputLine;
//				StringBuffer content = new StringBuffer();
//				while ((inputLine = in.readLine()) != null) {
//				    content.append(inputLine);
//				}
//				in.close();
//				JSONParser parser = new JSONParser();
//				JSONObject json = (JSONObject) parser.parse(content.toString());
//				String pwd = (String) json.get("Content");
				String pwd = password;
	    		if(tecnologia.equals("DB2"))
					additionalParams = ":securityMechanism=9;encryptionAlgorithm=2;defaultIsolationLevel=1;";
	    		Connection connessione = toolbox.prepareDBConnection(databaseType.valueOf(tecnologia), host, port, sid_service, additionalParams, username, pwd);
	    		
	    		logger.info(checkQuery + " FROM " + schema + ".\"" + tableName + "\"");
				ResultSet risultato = toolbox.executeQuery(connessione, checkQuery + " FROM " + schema + ".\"" + tableName + "\"");
				ResultSet result_exp = toolbox.executeQuery(connessione, "SELECT C.COLUMN_ID, B.VALUE, B.RES_ATTESO FROM "+db_schema+".CHECK_2 AS C JOIN "+db_schema+".CHECK_LINK AS L ON C.ID = L.ID_CHECK JOIN CHECK_BASE AS B ON L.ID_BASE = B.ID WHERE DATABASE_ID = '"+db+"' AND TABLE_ID = '"+table+"'");
				// 
	    		JSONObject totalResult = new JSONObject();
	    		ResultSetMetaData meta = risultato.getMetaData();
	    		int colCount = meta.getColumnCount();
				/* ArrayList<String> algos = condizione.getValues();
				int ln = algos.size(); */
	    		while(risultato.next())
	    		{
	    		    for (int c=1; c <= colCount; c++) 
	    		    {
	    		    	HashMap<String, String> val = new HashMap<String, String>();
						HashMap<String, String> val_exp = new HashMap<String, String>();
	    		    	String results = risultato.getString(c);
						// Connection conn = toolbox.prepareDBConnection(databaseType.valueOf(tecnologia), host, port, sid_service, additionalParams, username, pwd);
						/* ResultSet res_set = toolbox.executeQuery(conn, "SELECT COUNT(DISTINCT NAME) FROM "+db_schema+".CHECK_ALGO WHERE LEGAL_ENTITY = '" + legalEntity + "'");
						res_set.next();
						int alg_count = res_set.getInt(1);
						conn.close(); */
	    		    	if(results != null)
		    		    	if(results.split(":;", -1).length-1 != 2 && // check verifica bug in scrittura (?)
								results.split(":0", -1).length-1 != wheres.get(c).getValues().size()) { // check verfiica almeno un match
			    		    	String types[] = results.split(";");
			    		    	for (String t:types) {
			    		    		String values[] = t.split(":");
			    		    		if(!values[1].equals("0"))
			    		    			val.put(values[0], values[1]);
			    		    	}
			    		    	// totalResult.put(val.keySet().toArray(), val.get(val.keySet().toArray()));
								totalResult.put(meta.getColumnName(c), val);
								// totalResult.putAll(val);

								// costruzione struttura dati per confronto risultati
								while(result_exp.next()) {
									if(result_exp.getString(1).equals(meta.getColumnName(c))) {
										val_exp.put(result_exp.getString(2), result_exp.getString(3));
									}
								}
								ResultValue result = new ResultValue(meta.getColumnName(c));
								result.setValues(val);
								result.setValuesExp(val_exp);
								// confronto risultati
								result.result_check();

							
							} else {
								totalResult.put("No matching values found", null);
							}
	    		    }

	    		}
				risultato.close();
				result_exp.close();
				
				// Object[] keys_arr = totalResult.keySet().toArray();
			if(!(totalResult.isEmpty())) {
				for(int i = 0; i < totalResult.keySet().size(); i++ ) {
					ResultSet write_result = toolbox.executeQuery(connessione, "UPDATE "+db_schema+".CHECK_2 SET RESULT = '"+totalResult.get(totalResult.keySet().toArray()[i])+"' WHERE COLUMN_ID = '"+totalResult.keySet().toArray()[i]+"' AND DATABASE_ID = '"+db+"' AND TABLE_ID = '"+table+"'");
					write_result.close();
				}
				
				} else { System.err.println("No value found in the table"); }
				// HashMap<String, String> results_check_map = new HashMap<String, String>();
				
					res.setValue(ByteBuffer.wrap(totalResult.toJSONString().getBytes(StandardCharsets.UTF_8)));
					// dovrebbe essere corretto l'ordine di inserimento, genericData è una mappa e res è il valore che corrisponde alla chiave result
					// quindi avendo più righe per result effettivamente corrisponderà ad un array dei valori, e sarà ordinato per come è
					// stato preso all'inizio
					// rimane il problema della scrittura di tutte le coppie valori-occorrenze in tutte le righe delle colonna 
					// result nella tabella, si può forzare una scrittura, come fatto sopra ma il metodomask ritorna un oggetto GenericData che andrà a
					// a sovrascrivere i valori al termine dell'algoritmo. Oppure valutare il valore che corrisponde alla chiave COLUMN_ID
					// in GenericData, suppondo il valore sia un array con i column_id, ma non saprei come iterare sui valori di column_id che 
					// corrispondono a table e database
					// in caso di scrittura forzata sarebbe
					currentDate.setValue(LocalDateTime.now());
					connessione.close();

		}
		connection.close();
		} catch (Exception e) {
        	StringWriter sw = new StringWriter();
        	e.printStackTrace(new PrintWriter(sw));
			// logger.info(sw.toString());
        	throw new MaskingException(sw.toString());
        }
		return genericData;
	}
	
	@Override
	public Map<String, MaskingType> listMaskedFields() {

        Map<String, MaskingType> maskedFields = new HashMap<String, MaskingType> ();

        maskedFields.put("DATABASE_ID", MaskingType.STRING);

        maskedFields.put("TABLE_ID", MaskingType.STRING);
        
        maskedFields.put("RESULT", MaskingType.BYTE_BUFFER);
        
        maskedFields.put("TIMESTAMP", MaskingType.LOCAL_DATE_TIME);

        return maskedFields;

    }
	
	@Override
	public String getName() {
		return "RansomCheck";
	}


}
