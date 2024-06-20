package com.utilities;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Properties;
//import java.util.Scanner;

public class Toolbox {

	public enum databaseType {
		ORACLE, DB2, MSSQL, MYSQL, POSTGRES
	};

	public Connection prepareDBConnection(databaseType dbType, String hostname, String port, String instance,
			String additionalParams, String username, String password) throws ClassNotFoundException, SQLException {
		try {
		Connection connection = null;
		if (dbType == databaseType.ORACLE) {
			Class.forName("oracle.jdbc.OracleDriver");
			String dbURL = new String("jdbc:oracle:thin:@" + hostname + ":" + port + "/" + instance);
			connection = DriverManager.getConnection(dbURL, username, password);
		} else if (dbType == databaseType.DB2) {
			Class.forName("com.ibm.db2.jcc.DB2Driver");
			String dbURL = new String("jdbc:db2://" + hostname + ":" + port + "/" + instance + additionalParams);
			connection = DriverManager.getConnection(dbURL, username, password);
		}
		else if (dbType == databaseType.POSTGRES) {
			Class.forName("org.postgresql.Driver");
			String dbURL = new String("jdbc:postgresql://" + hostname + ":" + port + "/" + instance + additionalParams);
			connection = DriverManager.getConnection(dbURL, username, password);
		}
		return connection;
	} catch(SQLException e) {
		throw new SQLException(e.getSQLState() +" \n "+ e.getStackTrace() +" \n" + e.getMessage());
	}
	}


	public ResultSet executeQuery(Connection conn, String query, int fetchSize) throws SQLException {
		PreparedStatement preparedStatement = conn.prepareStatement(query);
		ResultSet rs = preparedStatement.executeQuery();
		rs.setFetchSize(fetchSize);
		return rs;
	}

	public ResultSet executeQuery(Connection conn, String query) throws SQLException {
		PreparedStatement preparedStatement = conn.prepareStatement(query);
		ResultSet rs = preparedStatement.executeQuery();
		rs.setFetchSize(5000);
		return rs;
	}

	public String getProperty(String propFile, String propToRead) throws IOException {
		Properties prop = new Properties();
		prop.load(getClass().getResourceAsStream(propFile));
		return prop.getProperty(propToRead);
	}

	public String cleanString(String word) {
		return word.replaceAll("[^a-zA-Z0-9]", "");
	}

	public String formatDate(String dt, String srcFormat) throws ParseException {
		DateFormat sourceFormat = new SimpleDateFormat(srcFormat);
		Date sourceDate = sourceFormat.parse(dt);
		DateFormat targetFormat = new SimpleDateFormat("dd/MM/yyyy");
		return targetFormat.format(sourceDate);
	}

	public String encrypt(String cf, byte[] salt, MessageDigest md) throws NoSuchAlgorithmException {
		md.update(salt);
		byte[] bytes = md.digest(cf.getBytes());
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
		}
		return sb.toString();
	}

	public String sha512Compressor(String input) {
		String[] shas = input.split("(?<=\\G.{16})"); // migrate sha512Compressor to toolbox

		char[] sha1 = shas[0].toCharArray();
		char[] sha2 = shas[1].toCharArray();
		char[] sha3 = shas[2].toCharArray();
		char[] sha4 = shas[3].toCharArray();
		char[] sha5 = shas[4].toCharArray();
		char[] sha6 = shas[5].toCharArray();
		char[] sha7 = shas[6].toCharArray();
		char[] sha8 = shas[7].toCharArray();

		String output = new String();

		for (int i = 0; i < 16; i++) {
			output = output.concat(String
					.valueOf((sha1[i] + sha2[i] + sha3[i] + sha4[i] + sha5[i] + sha6[i] + sha7[i] + sha8[i]) % 10));
		}
		return output;
	}

	public String[] adjustPiva(String piva) {
		String[] toReturn = new String[2];
		String numbers = new String();
		int missing = 0;
		String zeros = new String();
		if (piva.matches("^[a-zA-Z]{2}[0-9]{5,11}$") || piva.matches("^[a-zA-Z]{0,2}[0-9]{14,16}$")) {
			toReturn[0] = piva.substring(0, 2);
			numbers = piva.substring(2, piva.length());
		} else {
			numbers = new String(piva);
		}
		if (numbers.length() < 11) {
			missing = 11 - numbers.length();
			for (int i = 0; i < missing; i++) {
				zeros = zeros.concat("0");
			}
		}
		toReturn[1] = zeros.concat(numbers);
		return toReturn;
	}

	public double sigmoid(String value) {
		double x = Double.valueOf(value);
		return (1 / (1 + Math.pow(Math.E, (-1 * x))));
	}

	public String getBankAccount(String iban, int start, int end) {
		return iban.substring(start, end);
	}

	public String recalculateIBANCodes(String iban) {

		int[] oddPositions = new int[300];
		oddPositions['0'] = 1;
		oddPositions['1'] = 0;
		oddPositions['2'] = 5;
		oddPositions['3'] = 7;
		oddPositions['4'] = 9;
		oddPositions['5'] = 13;
		oddPositions['6'] = 15;
		oddPositions['7'] = 17;
		oddPositions['8'] = 19;
		oddPositions['9'] = 21;
		oddPositions['A'] = 1;
		oddPositions['B'] = 0;
		oddPositions['C'] = 5;
		oddPositions['D'] = 7;
		oddPositions['E'] = 9;
		oddPositions['F'] = 13;
		oddPositions['G'] = 15;
		oddPositions['H'] = 17;
		oddPositions['I'] = 19;
		oddPositions['J'] = 21;
		oddPositions['K'] = 2;
		oddPositions['L'] = 4;
		oddPositions['M'] = 18;
		oddPositions['N'] = 20;
		oddPositions['O'] = 11;
		oddPositions['P'] = 3;
		oddPositions['Q'] = 6;
		oddPositions['R'] = 8;
		oddPositions['S'] = 12;
		oddPositions['T'] = 14;
		oddPositions['U'] = 16;
		oddPositions['V'] = 10;
		oddPositions['W'] = 22;
		oddPositions['X'] = 25;
		oddPositions['Y'] = 24;
		oddPositions['Z'] = 23;

		Integer[] evenPositions = new Integer[300];
		evenPositions['A'] = 10;
		evenPositions['B'] = 11;
		evenPositions['C'] = 12;
		evenPositions['D'] = 13;
		evenPositions['E'] = 14;
		evenPositions['F'] = 15;
		evenPositions['G'] = 16;
		evenPositions['H'] = 17;
		evenPositions['I'] = 18;
		evenPositions['J'] = 19;
		evenPositions['K'] = 20;
		evenPositions['L'] = 21;
		evenPositions['M'] = 22;
		evenPositions['N'] = 23;
		evenPositions['O'] = 24;
		evenPositions['P'] = 25;
		evenPositions['Q'] = 26;
		evenPositions['R'] = 27;
		evenPositions['S'] = 28;
		evenPositions['T'] = 29;
		evenPositions['U'] = 30;
		evenPositions['V'] = 31;
		evenPositions['W'] = 32;
		evenPositions['X'] = 33;
		evenPositions['Y'] = 34;
		evenPositions['Z'] = 35;

//		String firstPart=iban.substring(0,4);
		iban = iban.replaceAll("[^a-zA-Z0-9]", "");
		String rearranged = iban.substring(5);
		int result = 0;
		for (int i = 0; i < rearranged.length(); i++) {
			if ((i + 1) % 2 == 0) {
				if (String.valueOf(rearranged.charAt(i)).matches("[A-Z]"))
					result += evenPositions[rearranged.charAt(i)] - 10;
				else
					result += Integer.parseInt(String.valueOf(rearranged.charAt(i)));
			} else
				result += oddPositions[rearranged.charAt(i)];
		}
		String CIN = String.valueOf((char) (Arrays.asList(evenPositions).indexOf((result % 26 + 10))));

		rearranged = CIN.concat(iban.substring(5).concat("IT00"));
		String converted = new String("");
		for (int i = 0; i < rearranged.length(); i++) {
			if (String.valueOf(rearranged.charAt(i)).matches("[A-Z]"))
				converted = converted.concat(String.valueOf(evenPositions[rearranged.charAt(i)]));
			else
				converted = converted.concat(String.valueOf(rearranged.charAt(i)));
		}
		BigInteger number = new BigInteger(converted);
		BigInteger modulo = new BigInteger("97");
		BigInteger a = new BigInteger("98");
		String rs = String.valueOf(a.subtract(number.mod(modulo)));

		if (rs.length() == 1)
			rs = "0".concat(rs);
		String newIBAN = new String("IT" + rs + CIN + iban.substring(5));
		return newIBAN;
	}

	public String getCFNotationSurname(String surname) {
		surname = surname.replaceAll("[^a-zA-Z0-9]", "");

		String output = "";

		/* calcolo prime 3 lettere */
		int cont = 0;
		/* caso cognome minore di 3 lettere */
		if (surname.length() < 3) {
			output += surname;
			while (output.length() < 3)
				output += "X";
			cont = 3;
		}

		/* caso normale */
		for (int i = 0; i < surname.length(); i++) {
			if (cont == 3)
				break;
			if (surname.charAt(i) != 'A' && surname.charAt(i) != 'E' && surname.charAt(i) != 'I'
					&& surname.charAt(i) != 'O' && surname.charAt(i) != 'U') {
				output += Character.toString(surname.charAt(i));
				cont++;
			}
		}

		/* nel casoci siano meno di 3 consonanti */
		while (cont < 3) {
			for (int i = 0; i < surname.length(); i++) {
				if (cont == 3)
					break;
				if (surname.charAt(i) == 'A' || surname.charAt(i) == 'E' || surname.charAt(i) == 'I'
						|| surname.charAt(i) == 'O' || surname.charAt(i) == 'U') {
					output += Character.toString(surname.charAt(i));
					cont++;
				}
			}
		}

		return output;
	}

	public String padString(String in, int expLen) {
		int toPad = expLen - in.length();
		String out = in;
		for (int i = 0; i < toPad; i++)
			out = out.concat(" ");
		return out;
	}

	public boolean checkEmptyOrNull(String input) {
		return (input == null || input.trim().isEmpty() || input.trim().equalsIgnoreCase("null"));
	}

	public String getCFNotationName(String name) {
		name = name.replaceAll("[^a-zA-Z0-9]", "");

		String output = "";

		/* calcolo prime 3 lettere */
		int cont = 0;
		/* lettere nome */
		cont = 0;
		/* caso nome minore di 3 lettere */
		if (name.length() < 3) {
			output += name;
			while (output.length() < 3)
				output += "X";
			cont = 3;
		}

		/* caso normale */
		boolean jump = checkConsNum(name);
		for (int i = 0; i < name.length(); i++) {
			if (cont == 3)
				break;
			if (name.charAt(i) != 'A' && name.charAt(i) != 'E' && name.charAt(i) != 'I' && name.charAt(i) != 'O'
					&& name.charAt(i) != 'U') {
				if (jump && cont == 1) {
					jump = false;
					continue;
				}
				output += Character.toString(name.charAt(i));
				cont++;
			}
		}

		/* nel casoci siano meno di 3 consonanti */
		while (cont < 3) {
			for (int i = 0; i < name.length(); i++) {
				if (cont == 3)
					break;
				if (name.charAt(i) == 'A' || name.charAt(i) == 'E' || name.charAt(i) == 'I' || name.charAt(i) == 'O'
						|| name.charAt(i) == 'U') {
					output += Character.toString(name.charAt(i));
					cont++;
				}
			}
		}

		return output;
	}

	private boolean checkConsNum(String nm) {
		int cons = 0;
		for (int i = 0; i < nm.length(); i++) {
			if (nm.charAt(i) != 'A' && nm.charAt(i) != 'E' && nm.charAt(i) != 'I' && nm.charAt(i) != 'O'
					&& nm.charAt(i) != 'U') {
				cons++;
			}
		}
		if (cons >= 4)
			return true;
		else
			return false;
	}

	public int getEntropy(String input) {
		int[] letters = new int[300];
		letters['A'] = 1;
		letters['B'] = 2;
		letters['C'] = 3;
		letters['D'] = 4;
		letters['E'] = 5;
		letters['F'] = 6;
		letters['G'] = 7;
		letters['H'] = 8;
		letters['I'] = 9;
		letters['J'] = 10;
		letters['K'] = 21;
		letters['L'] = 22;
		letters['M'] = 22;
		letters['N'] = 23;
		letters['O'] = 24;
		letters['P'] = 25;
		letters['Q'] = 26;
		letters['R'] = 27;
		letters['S'] = 28;
		letters['T'] = 29;
		letters['U'] = 30;
		letters['V'] = 41;
		letters['W'] = 42;
		letters['X'] = 43;
		letters['Y'] = 44;
		letters['Z'] = 45;

		int entropy = 0;
		for (int i = 0; i < 3; i++) {
			entropy += (letters[(char) input.charAt(i)] * (i + 1));
		}

		if (entropy <= 135)
			entropy *= -1;

		return entropy;
	}

	public String getCFControlChar(String CF) {
		int sommaPari = 0;
		for (int i = 1; i <= 13; i += 2) {
			switch (CF.charAt(i)) {
			case '0': {
				sommaPari += 0;
				break;
			}
			case '1': {
				sommaPari += 1;
				break;
			}
			case '2': {
				sommaPari += 2;
				break;
			}
			case '3': {
				sommaPari += 3;
				break;
			}
			case '4': {
				sommaPari += 4;
				break;
			}
			case '5': {
				sommaPari += 5;
				break;
			}
			case '6': {
				sommaPari += 6;
				break;
			}
			case '7': {
				sommaPari += 7;
				break;
			}
			case '8': {
				sommaPari += 8;
				break;
			}
			case '9': {
				sommaPari += 9;
				break;
			}
			case 'A': {
				sommaPari += 0;
				break;
			}
			case 'B': {
				sommaPari += 1;
				break;
			}
			case 'C': {
				sommaPari += 2;
				break;
			}
			case 'D': {
				sommaPari += 3;
				break;
			}
			case 'E': {
				sommaPari += 4;
				break;
			}
			case 'F': {
				sommaPari += 5;
				break;
			}
			case 'G': {
				sommaPari += 6;
				break;
			}
			case 'H': {
				sommaPari += 7;
				break;
			}
			case 'I': {
				sommaPari += 8;
				break;
			}
			case 'J': {
				sommaPari += 9;
				break;
			}
			case 'K': {
				sommaPari += 10;
				break;
			}
			case 'L': {
				sommaPari += 11;
				break;
			}
			case 'M': {
				sommaPari += 12;
				break;
			}
			case 'N': {
				sommaPari += 13;
				break;
			}
			case 'O': {
				sommaPari += 14;
				break;
			}
			case 'P': {
				sommaPari += 15;
				break;
			}
			case 'Q': {
				sommaPari += 16;
				break;
			}
			case 'R': {
				sommaPari += 17;
				break;
			}
			case 'S': {
				sommaPari += 18;
				break;
			}
			case 'T': {
				sommaPari += 19;
				break;
			}
			case 'U': {
				sommaPari += 20;
				break;
			}
			case 'V': {
				sommaPari += 21;
				break;
			}
			case 'W': {
				sommaPari += 22;
				break;
			}
			case 'X': {
				sommaPari += 23;
				break;
			}
			case 'Y': {
				sommaPari += 24;
				break;
			}
			case 'Z': {
				sommaPari += 25;
				break;
			}
			}
		}
		int sommaDispari = 0;
		for (int i = 0; i <= 14; i += 2) {
			switch (CF.charAt(i)) {
			case '0': {
				sommaDispari += 1;
				break;
			}
			case '1': {
				sommaDispari += 0;
				break;
			}
			case '2': {
				sommaDispari += 5;
				break;
			}
			case '3': {
				sommaDispari += 7;
				break;
			}
			case '4': {
				sommaDispari += 9;
				break;
			}
			case '5': {
				sommaDispari += 13;
				break;
			}
			case '6': {
				sommaDispari += 15;
				break;
			}
			case '7': {
				sommaDispari += 17;
				break;
			}
			case '8': {
				sommaDispari += 19;
				break;
			}
			case '9': {
				sommaDispari += 21;
				break;
			}
			case 'A': {
				sommaDispari += 1;
				break;
			}
			case 'B': {
				sommaDispari += 0;
				break;
			}
			case 'C': {
				sommaDispari += 5;
				break;
			}
			case 'D': {
				sommaDispari += 7;
				break;
			}
			case 'E': {
				sommaDispari += 9;
				break;
			}
			case 'F': {
				sommaDispari += 13;
				break;
			}
			case 'G': {
				sommaDispari += 15;
				break;
			}
			case 'H': {
				sommaDispari += 17;
				break;
			}
			case 'I': {
				sommaDispari += 19;
				break;
			}
			case 'J': {
				sommaDispari += 21;
				break;
			}
			case 'K': {
				sommaDispari += 2;
				break;
			}
			case 'L': {
				sommaDispari += 4;
				break;
			}
			case 'M': {
				sommaDispari += 18;
				break;
			}
			case 'N': {
				sommaDispari += 20;
				break;
			}
			case 'O': {
				sommaDispari += 11;
				break;
			}
			case 'P': {
				sommaDispari += 3;
				break;
			}
			case 'Q': {
				sommaDispari += 6;
				break;
			}
			case 'R': {
				sommaDispari += 8;
				break;
			}
			case 'S': {
				sommaDispari += 12;
				break;
			}
			case 'T': {
				sommaDispari += 14;
				break;
			}
			case 'U': {
				sommaDispari += 16;
				break;
			}
			case 'V': {
				sommaDispari += 10;
				break;
			}
			case 'W': {
				sommaDispari += 22;
				break;
			}
			case 'X': {
				sommaDispari += 25;
				break;
			}
			case 'Y': {
				sommaDispari += 24;
				break;
			}
			case 'Z': {
				sommaDispari += 23;
				break;
			}
			}
		}
		int interoControllo = (sommaPari + sommaDispari) % 26;
		String carattereControllo = "";
		switch (interoControllo) {
		case 0: {
			carattereControllo = "A";
			break;
		}
		case 1: {
			carattereControllo = "B";
			break;
		}
		case 2: {
			carattereControllo = "C";
			break;
		}
		case 3: {
			carattereControllo = "D";
			break;
		}
		case 4: {
			carattereControllo = "E";
			break;
		}
		case 5: {
			carattereControllo = "F";
			break;
		}
		case 6: {
			carattereControllo = "G";
			break;
		}
		case 7: {
			carattereControllo = "H";
			break;
		}
		case 8: {
			carattereControllo = "I";
			break;
		}
		case 9: {
			carattereControllo = "J";
			break;
		}
		case 10: {
			carattereControllo = "K";
			break;
		}
		case 11: {
			carattereControllo = "L";
			break;
		}
		case 12: {
			carattereControllo = "M";
			break;
		}
		case 13: {
			carattereControllo = "N";
			break;
		}
		case 14: {
			carattereControllo = "O";
			break;
		}
		case 15: {
			carattereControllo = "P";
			break;
		}
		case 16: {
			carattereControllo = "Q";
			break;
		}
		case 17: {
			carattereControllo = "R";
			break;
		}
		case 18: {
			carattereControllo = "S";
			break;
		}
		case 19: {
			carattereControllo = "T";
			break;
		}
		case 20: {
			carattereControllo = "U";
			break;
		}
		case 21: {
			carattereControllo = "V";
			break;
		}
		case 22: {
			carattereControllo = "W";
			break;
		}
		case 23: {
			carattereControllo = "X";
			break;
		}
		case 24: {
			carattereControllo = "Y";
			break;
		}
		case 25: {
			carattereControllo = "Z";
			break;
		}
		}
		return carattereControllo;
	}

	public String checkSSNDigit(String inputStr) {
		int weights[] = { 3, 7, 9, 0, 5, 8, 4, 2, 1, 6 };
		String[] inputValueArr = inputStr.split("");
		int j = 0;
		int sum = 0;
		for (int i = 0; i < inputStr.length(); i++) {
			if (Integer.parseInt(inputValueArr[i]) != -1) {
				int num = Integer.parseInt(inputValueArr[i]);
				sum += (num * weights[j]);
				j += 1;
			}
		}
		String output = Integer.toString(sum);
		return output;
	}

	public String formula_di_luhn(String vat) {
		int pari = 0;
		int dispari = 0;
		vat = vat.trim();
		String[] inputValueArr = vat.split("");
		for (int i = 0; i < vat.length(); i++) {
			if (i % 2 == 0) {
				dispari += Integer.parseInt(inputValueArr[i]);
			} else {
				int check = Integer.parseInt(inputValueArr[i]);
				if (check >= 5) {
					pari += (check * 2) - 9;
				} else {
					pari += check * 2;
				}
			}
		}
		int tmp = (pari + dispari) % 10;
		int t = (10 - tmp) % 10;
		return Integer.toString(t);
	}

	public String checkTinDigit(String input) {
		ArrayList<Integer> k = new ArrayList<Integer>();
		String[] inputArr = input.split("");
		for (int i = 0; i < 8; i++) {
			int num = Integer.parseInt(inputArr[i]);
			if ((i % 2) == 0)
				k.add(num);
			else
				k.add(2 * num);
		}
		ArrayList<Integer> r = new ArrayList<Integer>();
		for (int j = 0; j < 8; j++) {
			if (k.get(j) <= 9)
				r.add(k.get(j));
			else
				r.add((k.get(j) % 10) + 1);
		}
		int sum = 0;
		for (int z = 0; z < 8; z++) {
			sum += r.get(z);
		}
		int out = (100 - sum) % 10;
		return Integer.toString(out);
	}

}
