package com.utilities;

import java.lang.reflect.Array;
import java.util.ArrayList;

import com.delphix.masking.api.plugin.utils.GenericData;


/* class that hold data of check_2 result table and table where reside column to extract values from */
public class TableDetails{
    // results table data
    private String db; // all  for security purposes 
    private String table;
    private String col;
    private GenericData result;
    private GenericData timestamp;
    // data required to connect to table where reside column to extract values from
    private String technology;
    private String host;
    private String port;
    private String sid;
    private String schema;
    private String username;
    private String password;

    private ArrayList<String> null_values;
    // builder for results table details
    public void setDetails(String db, String table, String col, GenericData result, GenericData timestamp) throws IllegalArgumentException {
        this.db = db==null ? addNullValue("db") : db;
        this.table = table==null ? addNullValue("table") : table;
        this.col = col==null ? addNullValue("col") : col;
        this.result = result;
        this.timestamp = timestamp;
        checkNullValues();
    }

    public void setDetails(String technology, String host, String port, String sid_service, String schema, String table, String col, String username, String password) throws IllegalArgumentException {
        this.technology = technology==null ? addNullValue("technology") : technology;
        this.host = host==null ? addNullValue("host") : host;
        this.port = port==null ? addNullValue("port") : port;
        this.sid = sid==null ? addNullValue("sid") : sid;
        this.schema = schema==null ? addNullValue("schema") : schema;
        this.table = table==null ? addNullValue("table") : table;
        this.col = col==null ? addNullValue("col") : col;
        this.username = username==null ? addNullValue("username") : username;
        this.password = password==null ? addNullValue("password") : password;
        checkNullValues();
    }

    //  handler for null values
    public String addNullValue(String value) {
        null_values.add(value);
        return "";
    }

    public void checkNullValues() throws IllegalArgumentException {
        if (!null_values.isEmpty()) {
            throw new IllegalArgumentException("Missing required parameter(s) to establish connection/perform query: " + String.join(" ,", null_values));
        }
    }


    // getters
    public String getDb() { return db; }
    public String getTable() { return table; }
    public String getCol() { return col; }
    public GenericData getResult() { return result; }
    public GenericData getTimestamp() { return timestamp; }
    public String getTech() { return technology; }
    public String getHost() { return host; }
    public String getPort() { return port; }
    public String getSid() { return sid; }
    public String getSchema() { return schema; }
    public String getUsr() { return username; }
    public String getPwd() { return password; }

}
