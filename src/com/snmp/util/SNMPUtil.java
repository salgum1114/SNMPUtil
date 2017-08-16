package com.snmp.util;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.Gauge32;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

/**
 * SNMPUtil
 * @author salgu_000
 *
 */
public class SNMPUtil {
	// Cisco Ping Mib
	public static final String ciscoPingProtocol = "1.3.6.1.4.1.9.9.16.1.1.1.2";
	public static final String ciscoPingAddress = "1.3.6.1.4.1.9.9.16.1.1.1.3";
	public static final String ciscoPingPacketCount = "1.3.6.1.4.1.9.9.16.1.1.1.4";
	public static final String ciscoPingPacketSize = "1.3.6.1.4.1.9.9.16.1.1.1.5";
	public static final String ciscoPingPacketTimeout = "1.3.6.1.4.1.9.9.16.1.1.1.6";
	public static final String ciscoPingDelay = "1.3.6.1.4.1.9.9.16.1.1.1.7";
	public static final String ciscoPingTrapOnCompletion = "1.3.6.1.4.1.9.9.16.1.1.1.8";
	public static final String ciscoPingSentPackets = "1.3.6.1.4.1.9.9.16.1.1.1.9";
	public static final String ciscoPingReceivedPackets = "1.3.6.1.4.1.9.9.16.1.1.1.10";
	public static final String ciscoPingMinRtt = "1.3.6.1.4.1.9.9.16.1.1.1.11";
	public static final String ciscoPingAvgRtt = "1.3.6.1.4.1.9.9.16.1.1.1.12";
	public static final String ciscoPingMaxRtt = "1.3.6.1.4.1.9.9.16.1.1.1.13";
	public static final String ciscoPingCompleted = "1.3.6.1.4.1.9.9.16.1.1.1.14";
	public static final String ciscoPingEntryOwner = "1.3.6.1.4.1.9.9.16.1.1.1.15";
	public static final String ciscoPingEntryStatus = "1.3.6.1.4.1.9.9.16.1.1.1.16";
	
	// DISMAN-PING-MIB
	public static final String pingCtlTargetAddressType = "1.3.6.1.2.1.80.1.2.1.3";
	public static final String pingCtlTargetAddress = "1.3.6.1.2.1.80.1.2.1.4";
	public static final String pingCtlDataSize = "1.3.6.1.2.1.80.1.2.1.5";
	public static final String pingCtlTimeOut = "1.3.6.1.2.1.80.1.2.1.6";
	public static final String pingCtlProbeCount = "1.3.6.1.2.1.80.1.2.1.7";
	public static final String pingCtlAdminStatus = "1.3.6.1.2.1.80.1.2.1.8";
	public static final String pingCtlDataFill = "1.3.6.1.2.1.80.1.2.1.9";
	public static final String pingCtlFrequency = "1.3.6.1.2.1.80.1.2.1.10";
	public static final String pingCtlMaxRows = "1.3.6.1.2.1.80.1.2.1.11";
	public static final String pingCtlStorageType = "1.3.6.1.2.1.80.1.2.1.12";
	public static final String pingCtlTrapGeneration = "1.3.6.1.2.1.80.1.2.1.13";
	public static final String pingCtlTrapProbeFailureFilter = "1.3.6.1.2.1.80.1.2.1.14";
	public static final String pingCtlTrapTestFailureFilter = "1.3.6.1.2.1.80.1.2.1.15";
	public static final String pingCtlType = "1.3.6.1.2.1.80.1.2.1.16";
	public static final String pingCtlDescr = "1.3.6.1.2.1.80.1.2.1.17";
	public static final String pingCtlSourceAddressType = "1.3.6.1.2.1.80.1.2.1.18";
	public static final String pingCtlSourceAddress = "1.3.6.1.2.1.80.1.2.1.19";
	public static final String pingCtlIfIndex = "1.3.6.1.2.1.80.1.2.1.20";
	public static final String pingCtlByPassRouteTable = "1.3.6.1.2.1.80.1.2.1.21";
	public static final String pingCtlDSField = "1.3.6.1.2.1.80.1.2.1.22";
	public static final String pingCtlRowStatus = "1.3.6.1.2.1.80.1.2.1.23";
	public static final String pingResultsOperStatus = "1.3.6.1.2.1.80.1.3.1.1";
	public static final String pingResultsIpTargetAddressType = "1.3.6.1.2.1.80.1.3.1.2";
	public static final String pingResultsIpTargetAddress = "1.3.6.1.2.1.80.1.3.1.3";
	public static final String pingResultsMinRtt = "1.3.6.1.2.1.80.1.3.1.4";
	public static final String pingResultsMaxRtt = "1.3.6.1.2.1.80.1.3.1.5";
	public static final String pingResultsAverageRtt = "1.3.6.1.2.1.80.1.3.1.6";
	public static final String pingResultsProbeResponses = "1.3.6.1.2.1.80.1.3.1.6";
	public static final String pingResultsSentProbes = "1.3.6.1.2.1.80.1.3.1.8";
	public static final String pingResultsRttSumOfSquares = "1.3.6.1.2.1.80.1.3.1.9";
	public static final String pingResultsLastGoodProbe = "1.3.6.1.2.1.80.1.3.1.10";
	
	public static final int RETRY = 2;
	public static final int TIMEOUT = 5000;
		
	public static void main(String[] args) {
		System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + "Arguments " + Arrays.toString(args));
		if("snmpv3test".equals(args[0])) {
			List<String> newList = Arrays.asList(args).subList(1, args.length);
			String[] newArray = newList.toArray(new String[newList.size()]);
			callSnmpV3CiscoTest(newArray);
//			callSnmpV3PublicTest(newArray);
		} else if("snmpsetv3".equals(args[0])) {
			List<String> newList = Arrays.asList(args).subList(1, args.length);
			String[] newArray = newList.toArray(new String[newList.size()]);
			callSnmpSetV3(newArray);
		} else if("snmpgetv3".equals(args[0])) {
			List<String> newList = Arrays.asList(args).subList(1, args.length);
			String[] newArray = newList.toArray(new String[newList.size()]);
			callSnmpGetV3(newArray);
		} else if("snmpgetv2c".equals(args[0])) {
			List<String> newList = Arrays.asList(args).subList(1, args.length);
			String[] newArray = newList.toArray(new String[newList.size()]);
			callSnmpGetV1V2(newArray);
		} else if("snmpsetv2c".equals(args[0])) {
			List<String> newList = Arrays.asList(args).subList(1, args.length);
			String[] newArray = newList.toArray(new String[newList.size()]);
			callSnmpSetV1V2(newArray);
		}
	}
	
	private static void callSnmpV3PublicTest(String[] args) {
		args = Arrays.copyOf(args, args.length+3);
		args = snmpSetV3Paramenter(args, pingCtlRowStatus+".3.116.101.115.1.116", "i", "6");
		callSnmpSetV3(args);
		Map<String, String> requestMap = new LinkedHashMap<String, String>();
		requestMap.put(pingCtlRowStatus+".3.116.101.115.1.116", "i 4");
		requestMap.put(pingCtlTargetAddressType+".3.116.101.115.1.116", "i 1");
		requestMap.put(pingCtlTargetAddress+".3.116.101.115.1.116", "s 192.168.0.1");
		requestMap.put(pingCtlProbeCount+".3.116.101.115.1.116", "u 3");
		requestMap.put(pingCtlDataSize+".3.116.101.115.1.116", "u 64");
		requestMap.put(pingCtlTimeOut+".3.116.101.115.1.116", "u 1");
		args = Arrays.copyOf(args, args.length-3);
		innerCallSnmpSetV3(args, requestMap);
		
		long innerTimeout = (3 * 1000) + 5000;
		long startTime = System.currentTimeMillis();
		long endTime = startTime + innerTimeout;
		boolean isTimeout = true;
		while(System.currentTimeMillis() <= endTime) {
			try {
				Thread.sleep(200);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			args = snmpGetV3Paramenter(args, pingCtlRowStatus+".3.116.101.115.1.116");
			Variable statusVar = callSnmpGetV3(args);
			if(statusVar != null) {
				if(statusVar.toInt() == 1) {
					System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : Retmote Pring Ready!!");
					args = Arrays.copyOf(args, args.length+2);
					args = snmpSetV3Paramenter(args, pingCtlAdminStatus+".3.116.101.115.1.116", "i", "1");
					callSnmpSetV3(args);
					isTimeout = false;
					break;
				} 
			}
		}
		
		String activeMessage = "";
		if(!isTimeout) {
			activeMessage = "Remote Ping Start!! [ " + args[0] + " ]";
			
		} else {
			throw new RuntimeException("Remote Ping Timeout !! [ " + args[0] + " ]");
		}
		System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + activeMessage);
		
		List<String> resultOidList = new ArrayList<String>();
		resultOidList.add(pingResultsMinRtt+".3.116.101.115.1.116");
		resultOidList.add(pingResultsMaxRtt+".3.116.101.115.1.116");
		resultOidList.add(pingResultsAverageRtt+".3.116.101.115.1.116");
		resultOidList.add(pingResultsSentProbes+".3.116.101.115.1.116");
		resultOidList.add(pingResultsProbeResponses+".3.116.101.115.1.116");
		while(System.currentTimeMillis() <= endTime) {
			try {
				Thread.sleep(200);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			args = snmpGetV3Paramenter(args, pingResultsOperStatus+".3.116.101.115.1.116");
			Variable completedVar = callSnmpGetV3(args);
			if(completedVar != null) {
				if(completedVar.toInt() == 2) {
					System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : Retmote Pring Completed!!");
					args = snmpGetV3Paramenter(args, pingResultsOperStatus+".3.116.101.115.1.116");
					Map<String, Variable> resMap = innerCallSnmpGetV3(args, resultOidList);
					System.out.println("Remote Ping from [ " + args[0] + " ] to [ " + "192.168.0.1" + " ] with 64 bytes of data.\n");
					System.out.println("---- [ " + "192.168.0.1" + " ] Remote Ping Statistics ----\n\n");
					makeRemotePingResult(resMap, resultOidList);
					isTimeout = false;
					break;
				}
			} 
		}
		
		String completedMessage = "";
		if(!isTimeout) {
			completedMessage = "Remote Ping Success!! [ " + args[0] + " ]";
			
		} else {
			throw new RuntimeException("Remote Ping Timeout !! [ " + args[0] + " ]");
		}
		
		args = Arrays.copyOf(args, args.length+2);
		args = snmpSetV3Paramenter(args, pingCtlRowStatus+".3.116.101.115.1.116", "i", "6");
		callSnmpSetV3(args);
		
		System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + completedMessage);
	}
	
	private static void callSnmpV3CiscoTest(String[] args) {
		args = Arrays.copyOf(args, args.length+3);
		args = snmpSetV3Paramenter(args, ciscoPingEntryStatus+".333", "i", "6");
		callSnmpSetV3(args);
		Map<String, String> requestMap = new LinkedHashMap<String, String>();
		requestMap.put(ciscoPingEntryStatus+".333", "i 4");
		requestMap.put(ciscoPingEntryOwner+".333", "s test");
		requestMap.put(ciscoPingProtocol+".333", "i 1");
		requestMap.put(ciscoPingAddress+".333", "x 172.27.1.12");
		requestMap.put(ciscoPingPacketCount+".333", "i 3");
		requestMap.put(ciscoPingPacketSize+".333", "i 64");
		requestMap.put(ciscoPingPacketTimeout+".333", "i 1000");
		args = Arrays.copyOf(args, args.length-3);
		innerCallSnmpSetV3(args, requestMap);
		
		long innerTimeout = (3 * 1000) + 1000;
		long startTime = System.currentTimeMillis();
		long endTime = startTime + innerTimeout;
		boolean isTimeout = true;
		while(System.currentTimeMillis() <= endTime) {
			try {
				Thread.sleep(200);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			args = snmpGetV3Paramenter(args, ciscoPingEntryStatus+".333");
			Variable statusVar = callSnmpGetV3(args);
			if(statusVar != null) {
				if(statusVar.toInt() == 1) {
					System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : Retmote Pring Ready!!");
					args = Arrays.copyOf(args, args.length+2);
					args = snmpSetV3Paramenter(args, ciscoPingEntryStatus+".333", "i", "1");
					callSnmpSetV3(args);
					isTimeout = false;
					break;
				}
			}
		}
		
		String activeMessage = "";
		if(!isTimeout) {
			activeMessage = "Remote Ping Start!! [ " + args[0] + " ]";
		} else {
			throw new RuntimeException("Remote Ping Timeout !! [ " + args[0] + " ]");
		}
		
		System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + activeMessage);
		
		List<String> resultOidList = new ArrayList<String>();
		resultOidList.add(ciscoPingMinRtt+".333");
		resultOidList.add(ciscoPingMaxRtt+".333");
		resultOidList.add(ciscoPingAvgRtt+".333");
		resultOidList.add(ciscoPingSentPackets+".333");
		resultOidList.add(ciscoPingReceivedPackets+".333");
		
		while(System.currentTimeMillis() <= endTime) {
			try {
				Thread.sleep(200);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			args = snmpGetV3Paramenter(args, ciscoPingCompleted+".333");
			Variable completedVar = callSnmpGetV3(args);
			if(completedVar != null) {
				if(completedVar.toInt() == 1) {
					System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : Retmote Pring Completed!!");
					args = snmpGetV3Paramenter(args, ciscoPingCompleted+".333");
					Map<String, Variable> resMap = innerCallSnmpGetV3(args, resultOidList);
					System.out.println("Remote ping " + args[0] + " 64 bytes of data.");
					System.out.println("----" + args[0] + " Remote Ping Statistics----\n");
					makeRemotePingResult(resMap, resultOidList);
					isTimeout = false;
					break;
				} 
			}
			
		}
		
		String completedMessage = "";
		if(!isTimeout) {
			completedMessage = "Remote Ping Success!! [ " + args[0] + " ]";
			
		} else {
			throw new RuntimeException("Remote Ping Timeout !! [ " + args[0] + " ]");
		}
		
		args = Arrays.copyOf(args, args.length+2);
		args = snmpSetV3Paramenter(args, ciscoPingEntryStatus+".333", "i", "6");
		callSnmpSetV3(args);
		
		System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + completedMessage);
	}
	
	private static String[] snmpSetV3Paramenter(String[] args, String oid, String dataType, String dataValue) {
		if(args.length == 11) {
			args[8] = oid;
			args[9] = dataType;
			args[10] = dataValue;
		} else if(args.length == 12) {
			args[9] = oid;
			args[10] = dataType;
			args[11] = dataValue;
		} else {
			throw new RuntimeException("Input arguments exception!! " + Arrays.toString(args));
		}
		
		return args;
	}
	
	private static String[] snmpGetV3Paramenter(String[] args, String oid) {
		if(args.length == 12 || args.length == 11) {
			args = Arrays.copyOf(args, args.length-2);
		}
		if(args.length ==  8) {
			args = Arrays.copyOf(args, args.length+1);
		}
		if(args.length == 10) {
			args[9] = oid;
		} else if(args.length == 9){
			args[8] = oid;
		} else {
			throw new RuntimeException("Input arguments exception!! " + Arrays.toString(args));
		}
		return args;
	}
	
	private static Variable callSnmpGetV1V2(String[] args) {
		System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : Arguments " + Arrays.toString(args));
		Variable retVar = null;
		String host = args[0].trim();
		int port = Integer.valueOf(args[1].trim());
		String paramOid = args[2].trim();
		String community = null;
		if(args.length > 3) {
			community = args[3].trim();
		}
		
		CommunityTarget comtarget = getV1V2Target(host, port, community);
		
		PDU pdu = new PDU();
		pdu.setType(PDU.GET);
		pdu.add(new VariableBinding(new OID(paramOid)));
		
		ResponseEvent event = null;
		Snmp snmp = null;
		try {
			snmp = getSnmpV1V2();
			event = snmp.send(pdu, comtarget);
		} catch (Exception e) {
			throw new RuntimeException("SnmpV3 Send Failed!!", e);
		} finally {
			if(snmp != null) {
				try {
					snmp.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
		
		PDU responsePDU = null;
		if(event != null) {
			responsePDU = event.getResponse();
		}

		if(responsePDU != null) {
			System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + responsePDU);
			if(responsePDU.getErrorStatus() == PDU.noError) {
				for (Object obj : responsePDU.getVariableBindings()) {
					if (obj instanceof VariableBinding) {
						VariableBinding vb = (VariableBinding) obj;
						retVar = vb.getVariable();
						System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + "OID. " + vb.getOid().toString() + ", Value. " + vb.getVariable());
					}
				}
			} else {
				throw new RuntimeException("SNMP Error. [" + responsePDU.getErrorStatusText() + "]");
			}
		} else {
			throw new RuntimeException("SNMP Timeout. Host[" + host + "], SNMPV2..");
		}
		
		return retVar;
	}
	
	private static Variable callSnmpSetV1V2(String[] args) {
		System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : Arguments " + Arrays.toString(args));
		Variable retVar = null;
		String host = args[0].trim();
		int port = Integer.valueOf(args[1].trim());
		String paramOid = args[2].trim();
		String community = null;
		if(args.length > 3) {
			community = args[3].trim();
		}
		String paramDataType = args[4];
		String paramDataValue = args[5];
		
		CommunityTarget comtarget = getV1V2Target(host, port, community);
		
		PDU pdu = new PDU();
		pdu.setType(PDU.SET);
		Variable dataVar = null;
		if("i".equals(paramDataType)) {
			dataVar = new Integer32(Integer.parseInt(paramDataValue));
		} else if("s".equals(paramDataType)) {
			dataVar = new OctetString(paramDataValue);
		} else if("x".equals(paramDataType)) {
			byte[] newBytes = convertIPtoBytes(paramDataValue);
			dataVar = new OctetString(newBytes);
		} else if("u".equals(paramDataType)) {
			dataVar = new Gauge32(Long.parseLong(paramDataValue));
		} else {
			throw new RuntimeException("Wrong Data Type!!");
		}
		pdu.add(new VariableBinding(new OID(paramOid), dataVar));
		
		ResponseEvent event = null;
		Snmp snmp = null;
		try {
			snmp = getSnmpV1V2();
			event = snmp.send(pdu, comtarget);
		} catch (Exception e) {
			throw new RuntimeException("SnmpV3 Send Failed!!", e);
		} finally {
			if(snmp != null) {
				try {
					snmp.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
		
		PDU responsePDU = null;
		if(event != null) {
			responsePDU = event.getResponse();
		}

		if(responsePDU != null) {
			System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + responsePDU);
			if(responsePDU.getErrorStatus() == PDU.noError) {
				for (Object obj : responsePDU.getVariableBindings()) {
					if (obj instanceof VariableBinding) {
						VariableBinding vb = (VariableBinding) obj;
						retVar = vb.getVariable();
						System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + "OID. " + vb.getOid().toString() + ", Value. " + vb.getVariable());
					}
				}
			} else {
				throw new RuntimeException("SNMP Error. [" + responsePDU.getErrorStatusText() + "]");
			}
		} else {
			throw new RuntimeException("SNMP Timeout. Host[" + host + "], SNMPV2..");
		}
		
		return retVar;
	}
	
	private static Variable callSnmpGetV3(String[] args) {
		System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : Arguments " + Arrays.toString(args));
		Variable retVar = null;
		String host = args[0];
		int port = Integer.valueOf(args[1]);
		String usmUser = args[2].trim();
		int securityLevel = getSecureLevel(args[3]);
		String authAlgorithm = args[4];
		String authPassword = args[5];
		String privacyAlgorithm = args[6];
		String privacyPassword = args[7];
		String paramOid = null;
		
		UserTarget target = getV3Target(host, port, securityLevel, usmUser);
		
		ScopedPDU pdu = new ScopedPDU();
		pdu.setType(ScopedPDU.GET);
		if(args.length > 9) {
			String contextName = args[8];
			pdu.setContextName(new OctetString(contextName));
			paramOid = args[9];
		} else {
			paramOid = args[8];
		}
		
		System.out.println(paramOid);
		pdu.add(new VariableBinding(new OID(paramOid)));
		
		ResponseEvent event = null;
		Snmp snmp = null;
		try {
			snmp = getSnmpV3(usmUser, authAlgorithm, authPassword, privacyAlgorithm, privacyPassword);
			event = snmp.send(pdu, target);
		} catch (Exception e) {
			throw new RuntimeException("SnmpV3 Send Failed!!", e);
		} finally {
			if(snmp != null) {
				try {
					snmp.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
		
		PDU responsePDU = null;
		if(event != null) {
			responsePDU = event.getResponse();
		}

		if(responsePDU != null) {
			System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + responsePDU);
			if(responsePDU.getErrorStatus() == PDU.noError) {
				for (Object obj : responsePDU.getVariableBindings()) {
					if (obj instanceof VariableBinding) {
						VariableBinding vb = (VariableBinding) obj;
						retVar = vb.getVariable();
						System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + "OID. " + vb.getOid().toString() + ", Value. " + vb.getVariable());
					}
				}
			} else {
				throw new RuntimeException("SNMP Error. [" + responsePDU.getErrorStatusText() + "]");
			}
		} else {
			throw new RuntimeException("SNMP Timeout. Host[" + host + "], SNMPV3..");
		}
		
		return retVar;
	}
	
	private static Map<String, Variable> innerCallSnmpGetV3(String[] args, List<String> oids) {
		System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : Arguments " + Arrays.toString(args));
		Map<String, Variable> retMap = new LinkedHashMap<String, Variable>();
		String host = args[0];
		int port = Integer.valueOf(args[1]);
		String usmUser = args[2];
		int securityLevel = getSecureLevel(args[3]);
		String authAlgorithm = args[4];
		String authPassword = args[5];
		String privacyAlgorithm = args[6];
		String privacyPassword = args[7];
		
		UserTarget target = getV3Target(host, port, securityLevel, usmUser);
		
		ScopedPDU pdu = new ScopedPDU();
		pdu.setType(PDU.GET);
		if(args.length > 9) {
			String contextName = args[8];
			pdu.setContextName(new OctetString(contextName));
		}
		
		for(String oid : oids) {
			pdu.add(new VariableBinding(new OID(oid)));
		}
		
		ResponseEvent event = null;
		Snmp snmp = null;
		try {
			snmp = getSnmpV3(usmUser, authAlgorithm, authPassword, privacyAlgorithm, privacyPassword);
			
			event = snmp.send(pdu, target);
		} catch (Exception e) {
			throw new RuntimeException("SnmpV3 Send Failed!!", e);
		} finally {
			if(snmp != null) {
				try {
					snmp.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
		
		PDU responsePDU = null;
		if(event != null) {
			responsePDU = event.getResponse();
		}
		
		if(responsePDU != null) {
			System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + responsePDU);
			if(responsePDU.getErrorStatus() == PDU.noError) {
				for (Object obj : responsePDU.getVariableBindings()) {
					if (obj instanceof VariableBinding) {
						VariableBinding vb = (VariableBinding) obj;
						retMap.put(vb.getOid().toString(), vb.getVariable());
						System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : OID. " + vb.getOid().toString() + ", Value. " + vb.getVariable());
					}
				}
			} else {
				throw new RuntimeException("SNMP Error. [" + responsePDU.getErrorStatusText() + "]");
			}
		} else {
			throw new RuntimeException("SNMP Timeout. Host[" + host + "], SNMPV3..");
		}
		
		return retMap;
	}
	
	private static Map<String, Variable> innerCallSnmpSetV3(String[] args, Map<String, String> requestMap) {
		System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : Arguments " + Arrays.toString(args));
		Map<String, Variable> retMap = new LinkedHashMap<String, Variable>();
		String host = args[0];
		int port = Integer.valueOf(args[1]);
		String usmUser = args[2];
		int securityLevel = getSecureLevel(args[3]);
		String authAlgorithm = args[4];
		String authPassword = args[5];
		String privacyAlgorithm = args[6];
		String privacyPassword = args[7];
		UserTarget target = getV3Target(host, port, securityLevel, usmUser);
		
		ScopedPDU pdu = new ScopedPDU();
		pdu.setType(PDU.SET);
		System.out.println(args.length);
		if(args.length > 8) {
			System.out.println(args[8]);
			String contextName = args[8];
			pdu.setContextName(new OctetString(contextName));
		}
		
		for(Map.Entry<String, String> entry : requestMap.entrySet()) {
			String oid = entry.getKey();
			String[] value = entry.getValue().split(" ");
			String paramDataType = value[0];
			String paramDataValue = value[1];
			Variable dataVar = null;
			if("i".equals(paramDataType)) {
				dataVar = new Integer32(Integer.parseInt(paramDataValue));
			} else if("s".equals(paramDataType)) {
				dataVar = new OctetString(paramDataValue);
			} else if("x".equals(paramDataType)) {
				byte[] newBytes = convertIPtoBytes(paramDataValue);
				dataVar = new OctetString(newBytes);
			} else if("u".equals(paramDataType)) {
				dataVar = new Gauge32(Long.parseLong(paramDataValue));
			} else {
				throw new RuntimeException("Wrong Data Type!!");
			}
			System.out.println(paramDataValue);
			pdu.add(new VariableBinding(new OID(oid), dataVar));
		}
		
		ResponseEvent event = null;
		Snmp snmp = null;
		try {
			snmp = getSnmpV3(usmUser, authAlgorithm, authPassword, privacyAlgorithm, privacyPassword);
			
			event = snmp.send(pdu, target);
		} catch (Exception e) {
			throw new RuntimeException("SnmpV3 Send Failed!!", e);
		} finally {
			if(snmp != null) {
				try {
					snmp.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
		
		PDU responsePDU = null;
		if(event != null) {
			responsePDU = event.getResponse();
		}
		
		if(responsePDU != null) {
			System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + responsePDU);
			if(responsePDU.getErrorStatus() == PDU.noError) {
				for (Object obj : responsePDU.getVariableBindings()) {
					if (obj instanceof VariableBinding) {
						VariableBinding vb = (VariableBinding) obj;
						retMap.put(vb.getOid().toString(), vb.getVariable());
						System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : OID. " + vb.getOid().toString() + ", Value. " + vb.getVariable());
					}
				}
			} else {
				throw new RuntimeException("SNMP Error. [" + responsePDU.getErrorStatusText() + "]");
			}
		} else {
			throw new RuntimeException("SNMP Timeout. Host[" + host + "], SNMPV3..");
		}
		
		return retMap;
	}
	
	private static void callSnmpSetV3(String[] args) {
		System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : Arguments " + Arrays.toString(args));
		String host = args[0];
		int port = Integer.valueOf(args[1]);
		String usmUser = args[2];
		int securityLevel = getSecureLevel(args[3]);
		String authAlgorithm = args[4];
		String authPassword = args[5];
		String privacyAlgorithm = args[6];
		String privacyPassword = args[7];
		String paramOid = null;
		String paramDataType = null;
		String paramDataValue = null;
		
		UserTarget target = getV3Target(host, port, securityLevel, usmUser);
		
		
		ScopedPDU pdu = new ScopedPDU();
		pdu.setType(PDU.SET);
		if(args.length == 11) {
			paramOid = args[8];
			paramDataType = args[9];
			paramDataValue = args[10];
		} else if(args.length == 12) {
			String contextName = args[8];
			pdu.setContextName(new OctetString(contextName));
			paramOid = args[9];
			paramDataType = args[10];
			paramDataValue = args[11];
		}
		
		Variable dataVar = null;
		if("i".equals(paramDataType)) {
			dataVar = new Integer32(Integer.parseInt(paramDataValue));
		} else if("s".equals(paramDataType)) {
			dataVar = new OctetString(paramDataValue);
		} else if("x".equals(paramDataType)) {
			byte[] newBytes = convertIPtoBytes(paramDataValue);
			dataVar = new OctetString(newBytes);
		} else if("u".equals(paramDataType)) {
			dataVar = new Gauge32(Long.parseLong(paramDataValue));
		} else {
			throw new RuntimeException("Wrong Data Type!!");
		}
		pdu.add(new VariableBinding(new OID(paramOid), dataVar));
		
		ResponseEvent event = null;
		Snmp snmp = null;
		try {
			snmp = getSnmpV3(usmUser, authAlgorithm, authPassword, privacyAlgorithm, privacyPassword);
			
			event = snmp.send(pdu, target);
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if(snmp != null) {
				try {
					snmp.close();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
		
		PDU responsePDU = null;
		
		if(event != null) {
			responsePDU = event.getResponse();
		}
		
		if(responsePDU != null) {
			System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + responsePDU);
			if(responsePDU.getErrorStatus() == PDU.noError) {
				for (Object obj : responsePDU.getVariableBindings()) {
					if (obj instanceof VariableBinding) {
						VariableBinding vb = (VariableBinding) obj;
						System.out.println(new Throwable().getStackTrace()[0].getLineNumber() + " line : " + "OID. " + vb.getOid().toString() + ", Value. " + vb.getVariable());
					}
				}
			} else {
				throw new RuntimeException(responsePDU.getErrorStatusText());
			}
		} else {
			throw new RuntimeException("SNMP Timeout. Host[" + host + "], SNMPV3..");
		}
	}
	
	private static Snmp getSnmpV1V2() {
		Snmp snmp = null;
		try {
			snmp = new Snmp(new DefaultUdpTransportMapping());
			snmp.listen();
		} catch (IOException e) {
			if(snmp != null) {
				try {
					snmp.close();
				} catch (IOException e1) {
					throw new RuntimeException(e1);
				}
			}
		}
		return snmp;
	}
	
	// SecurityModels singleton use
	private static Snmp getSnmpV3(String usmUser, String authAlgorithm, String authPassword, String privacyAlgorithm, String privacyPassword) {
		TransportMapping<?> transport = null;
		 Snmp snmp = null;
		try {
			transport = new DefaultUdpTransportMapping();
	        snmp = new Snmp(transport);
	        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(
	                MPv3.createLocalEngineID()), 0);
	        SecurityModels.getInstance().addSecurityModel(usm);
	        
	        snmp.getUSM().addUser(new OctetString(usmUser), makeUsmUser(usmUser, authAlgorithm, authPassword, privacyAlgorithm, privacyPassword));
	        snmp.listen();
		} catch (Exception e) {
			if(snmp != null) {
				try {
					snmp.close();
				} catch (IOException e1) {
					throw new RuntimeException(e1);
				}
			}
			throw new RuntimeException("SnmpV3 not available!", e);
		}
		
		return snmp;
	}
	
	private static String makeRemotePingResult(Map<String, Variable> resultMap, List<String> resultOidList) {
		StringBuilder sb = new StringBuilder();
		
		int minRtt = 0;
		int maxRtt = 0;
		int avgRtt = 0;
		long sendPacket = 0;
		long receivePacket = 0;
		long lossPercent = 0;
		if(!resultMap.isEmpty()) {
			Variable minVar = resultMap.get(resultOidList.get(0));
			Variable maxVar = resultMap.get(resultOidList.get(1));
			Variable avgVar = resultMap.get(resultOidList.get(2));
			Variable sendPacketVar = resultMap.get(resultOidList.get(3));
			Variable receivePacketVar = resultMap.get(resultOidList.get(4));
			
			if(sendPacketVar != null) {
				sendPacket = sendPacketVar.toLong();
			}
			if(receivePacketVar != null) {
				receivePacket = receivePacketVar.toLong();
			}
			if(sendPacket != 0) {
				lossPercent = 100 - (receivePacket / sendPacket) * 100;
			}
			if(minVar != null) {
				minRtt = minVar.toInt();
			}
			if(maxVar != null) {
				maxRtt = maxVar.toInt();
			}
			if(avgVar != null) {
				avgRtt = avgVar.toInt();
			}
		}
		
		sb.append("    Packets:  ");
		sb.append(sendPacket);
		sb.append(" packets transmitted,  ");
		sb.append(receivePacket);
		sb.append(" packets received,  ");
		sb.append(lossPercent);
		sb.append(" % packet loss");
		sb.append("\n");
		sb.append("    Round-trips(ms):  ");
		sb.append(" Minimum = ");
		sb.append(minRtt + " ms");
		sb.append(",  Average = ");
		sb.append(avgRtt + " ms");
		sb.append(",  Maximum = ");
		sb.append(maxRtt + " ms");
		
		System.out.println(sb.toString());
		
		return sb.toString();
	}
	
	private static CommunityTarget getV1V2Target(String host, int port, String community) {
		CommunityTarget comtarget = new CommunityTarget();
		comtarget.setCommunity(new OctetString(community));
		comtarget.setVersion(SnmpConstants.version2c);
		comtarget.setAddress(new UdpAddress(host + "/" + port));
		comtarget.setRetries(RETRY);
		comtarget.setTimeout(TIMEOUT);
		return comtarget;
	}
	
	private static UserTarget getV3Target(String host, int port, int securityLevel, String usmUser) {
		Address targetAddress = GenericAddress.parse("udp:" + host + "/" + port);
		UserTarget target = new UserTarget();
		target.setAddress(targetAddress);
		target.setRetries(RETRY);
		target.setTimeout(TIMEOUT);
		target.setVersion(SnmpConstants.version3);
		target.setSecurityLevel(securityLevel);
		target.setSecurityName(new OctetString(usmUser));
		return target;
	}
	
	private static byte[] convertIPtoBytes(String reqIpAddr) {
		byte[] newBytes = null;
		try {
			InetAddress addr = InetAddress.getByName(reqIpAddr);
			newBytes = addr.getAddress();
		} catch (UnknownHostException e) {
			newBytes = new byte[0];
		}
		return newBytes;
	}
	
	public static UsmUser makeUsmUser(String usmU, String authAlgorithm, String authPassword, String priAlgorithm, String priPassword) {
		OctetString usmUser = new OctetString(usmU);
		OctetString authPass = null;
		OctetString priPass = null;
		OID authAlgotithmOID = null;
		OID priAlgorithmOID = null;
		
		if(authAlgorithm!=null){
			authAlgotithmOID = getAuthAlgorithmOID(authAlgorithm);
			if(authPassword==null){
				throw new RuntimeException("authenticationPassphrase required.");
			}
			authPass = new OctetString(authPassword.toString());
		}
		if(priAlgorithm!=null){
			priAlgorithmOID = getPrivacyAlgorithmOID(priAlgorithm);
			if(priPassword==null){
				throw new RuntimeException("privacyPassphrase required.");
			}
			priPass = new OctetString(priPassword.toString());
		}
		return new UsmUser(usmUser, authAlgotithmOID,
						authPass, priAlgorithmOID, priPass);
	}
	
	public static OID getAuthAlgorithmOID(String authAlgorithm) {
		if(authAlgorithm==null || authAlgorithm.equals("")){
			return null;
		}
		OID result = AuthMD5.ID;
		if (authAlgorithm.equals(AuthAlgorithm.MD5.toString())) {
			result = AuthMD5.ID;
		} else if (authAlgorithm.equals(AuthAlgorithm.SHA.toString())) {
			result = AuthSHA.ID;
		}
		return result;
	}
	
	public static OID getPrivacyAlgorithmOID(String privacyAlgorithm) {
		if(privacyAlgorithm==null || privacyAlgorithm.equals("")){
			return null;
		}
		OID result = PrivDES.ID;
		if (privacyAlgorithm.equals(PrivacyAlgorithm.DES3.toString())) {
			result = Priv3DES.ID;
		} else if (privacyAlgorithm.equals(PrivacyAlgorithm.AES128.toString())) {
			result = PrivAES128.ID;
		} else if (privacyAlgorithm.equals(PrivacyAlgorithm.AES192.toString())) {
			result = PrivAES192.ID;
		} else if (privacyAlgorithm.equals(PrivacyAlgorithm.AES256.toString())) {
			result = PrivAES256.ID;
		} else if (privacyAlgorithm.equals(PrivacyAlgorithm.DES.toString())) {
			result = PrivDES.ID;
		}
		return result;
	}
	
	public static int getSecureLevel(String sl) {
		int res = SecurityLevel.NOAUTH_NOPRIV;
		if (sl.equals(SecureLevel.NOAUTH_NOPRIVACY.toString())) {
			res = SecurityLevel.NOAUTH_NOPRIV;
		} else if (sl.equals(SecureLevel.AUTH_NOPRIVACY.toString())) {
			res = SecurityLevel.AUTH_NOPRIV;
		} else if (sl.equals(SecureLevel.AUTH_PRIVACY.toString())) {
			res = SecurityLevel.AUTH_PRIV;
		}

		return res;
	}
	
	public enum AuthAlgorithm {
		MD5, SHA
	}
	
	public enum SecureLevel {
		NOAUTH_NOPRIVACY, AUTH_NOPRIVACY, AUTH_PRIVACY
	}
	
	public enum PrivacyAlgorithm {
		DES3, AES128, AES192, AES256, DES
	}
	
}