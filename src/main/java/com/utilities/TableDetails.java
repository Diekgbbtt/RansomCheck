package com.utilities;

import com.delphix.masking.api.plugin.utils.GenericData;


/* class that hold data of check_2 result table and table where reside column to extract values from */
public class TableDetails{
    // results table data
    private final String db; // all final for security purposes 
    private final String table;
    private final String col;
    private final GenericData result;
    private final GenericData timestamp;
    // data required to connect to table where reside column to extract values from
    private final String technology;
    private final String host;
    private final String port;
    private final String sid;
    private final String schema;
    private final String username;
    private final String password;

    // builder for results table details
    public TableDetails(String db, String table, String col, GenericData result, GenericData timestamp) {
        this.db = db;
        this.table = table;
        this.col = col;
        this.result = result;
        this.timestamp = timestamp;
    }

    // builder for target table deatils
    public TableDetails(String technology, String host, String port, String sid_service, String schema, String username, String password, String db, String table, String col) {
        this.technology = technology;
        this.host = host;
        this.port = port;
        this.sid = sid_service;
        this.schema = schema;
        this.username = username;
        this.password = password;
        this.db = db;
        this.table = table;
        this.col = col;
    }

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
