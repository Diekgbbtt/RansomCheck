package com.algotesting;

import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.HashMap;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.Mock;
import org.mockito.Mockito;
import static org.mockito.Mockito.when;

import com.delphix.masking.api.plugin.utils.GenericData;
import com.delphix.masking.api.plugin.utils.GenericDataRow;
import com.sample.RansomCheck;
import com.utilities.TableDetails;
import com.utilities.Toolbox;



public class RansomCheckTest {

    RansomCheck ransomAlgo = new RansomCheck();
    LocalDateTime tmpTs = null;
    ByteBuffer tmpBuffer = null;
    HashMap<String, GenericData> tmpMap = new HashMap<>();
    GenericDataRow row = null;
    @Mock
    private Toolbox toolbox;
    @Mock
    private Connection mockConnection;
    @Mock
    private ResultSet mockResultSet;


    @BeforeEach
    public void setUp() {
        ransomAlgo.setup(Mockito.mock(com.delphix.masking.api.provider.ComponentService.class));
        tmpMap.put("DATABASE_ID", new GenericData("623", false));
        tmpMap.put("TABLE_ID", new GenericData("28", false));
        tmpMap.put("COLUMN_ID", new GenericData("77", false));
        tmpMap.put("RESULT", new GenericData(tmpBuffer, false));
        tmpMap.put("TIMESTAMP", new GenericData(tmpTs, false));
        GenericDataRow row = GenericDataRow.from(tmpMap);
    }

    @Test
    void testGetResultRow() {
        Assertions.assertEquals(null, this.ransomAlgo.resultRowData);
        ransomAlgo.getResultRowData(this.row);
        TableDetails tmpTable = new TableDetails();
        tmpTable.setDetails("623", "28", "77", new GenericData(tmpBuffer, false), new GenericData(tmpTs, false));
        Assertions.assertEquals(tmpTable, ransomAlgo.resultRowData);
    }

    @Test
    void testGetTargetTableData() throws SQLException, ClassNotFoundException {

        // Setup
        when(toolbox.prepareDBConnection(any(), anyString(), anyString(), anyString(), 
        anyString(), anyString(), anyString())).thenReturn(mockConnection);
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(1)).thenReturn("ORACLE");
        when(mockResultSet.getString(2)).thenReturn("host1");
        when(mockResultSet.getString(3)).thenReturn("1521");
        when(mockResultSet.getString(4)).thenReturn("ORCL");
        when(mockResultSet.getString(5)).thenReturn("schema1");
        when(mockResultSet.getString(6)).thenReturn("table1");
        when(mockResultSet.getString(7)).thenReturn("column1");
        when(mockResultSet.getString(8)).thenReturn("user1");
        when(mockResultSet.getString(9)).thenReturn("pass1");

        when(toolbox.executeQuery(eq(mockConnection), anyString(), any())).thenReturn(mockResultSet);
        TableDetails tmpTable = new TableDetails();
        tmpTable.setDetails("ORACLE", "host1", "1521", "ORCL", "schema1", "table1", "column1", "user1", "pass1");
        // Execute
        try {
            ransomAlgo.getTargetTableData();
        } catch (Exception e) { }

        // Verify
        Assertions.assertEquals(tmpTable, ransomAlgo.targetTableData);

    }

}
