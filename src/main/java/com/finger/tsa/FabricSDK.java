package com.finger.tsa;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeoutException;

import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.ContractException;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import com.finger.tsa.util.Util;

@Component
@Configuration
public class FabricSDK {

	private static final Logger logger = LoggerFactory.getLogger(FabricSDK.class); 

	@Value("${hyperledger.walletPath}")
	private String WALLET_PATH;
	@Value("${hyperledger.connectionConfig}")
	private String CONNECTION_CONFIG;
	@Value("${hyperledger.channelName}")
	private String channelName; 
	@Value("${hyperledger.chaincodeName}")
	private String chaincodeName; 
	@Value("${hyperledger.queryBySeqMethodName}")
	private String queryBySeqMethodName;
	@Value("${hyperledger.queryByHashMethodName}")
	private String queryByHashMethodName;
	@Value("${hyperledger.invokeMethodName}")
	private String invokeMethodName; 
	
	
	
	private Gateway getHLFGateway() throws IOException {
		try {
			logger.debug("#### START getHLFGateway ####");
			Path walletPath = Paths.get(Util.resourcesUrlPath(WALLET_PATH));
			Path networkConfigPath = Paths.get(Util.resourcesUrlPath(CONNECTION_CONFIG));
			//Path walletPath = Paths.get(WALLET_PATH);
			//Path networkConfigPath = Paths.get(CONNECTION_CONFIG);

			Wallet wallet = Wallet.createFileSystemWallet(walletPath);
			Gateway.Builder builder = Gateway.createBuilder();
			builder.identity(wallet, "nonghyupit").networkConfig(networkConfigPath).discovery(false);

			Gateway gateway = builder.connect();
			return gateway; 
		} catch (IOException e) {
			logger.error("[getHLFGateway] IOException :"+ e.getMessage());
			throw e; 
		}
	}
	
	public Contract getContract(String channelName, String chaincodeName) throws IOException {
		try {
			logger.debug("#### START getContract ####");
			Gateway gateway = getHLFGateway();
			Network network = gateway.getNetwork(channelName);
			return network.getContract(chaincodeName);
		} catch(IOException e) {
			logger.error("[getContract] IOException :"+ e.getMessage());
			throw e;
		}
	}
	
	public boolean invokeTrasaction(Object obj) throws ContractException, TimeoutException, InterruptedException, ParseException, IOException {
		Contract contract = getContract(channelName, chaincodeName); //하이퍼렛저 채널,체인코드에 연결 
		contract.submitTransaction(invokeMethodName, obj.toString()); //하이퍼렛저에 전달 후 결과 받음. 
		return true; 
	}
	
	public String evaluateTransctionByHash(String hashedStringFromPdfAddedToken) throws ContractException, IOException, ParseException {
		Contract contract = getContract(channelName, chaincodeName); //하이퍼렛저 채널,체인코드에 연결 
		byte[] byteResult = contract.evaluateTransaction(queryByHashMethodName, hashedStringFromPdfAddedToken);
		String StringResult = new String(byteResult);
		logger.debug("조회결과: "+StringResult);
		return StringResult; 
	}

	public String evaluateTransctionBySeq(String hashedStringFromPdfAddedToken) throws ContractException, IOException, ParseException {
		Contract contract = getContract(channelName, chaincodeName); //하이퍼렛저 채널,체인코드에 연결 
		byte[] byteResult = contract.evaluateTransaction(queryBySeqMethodName, hashedStringFromPdfAddedToken);
		String StringResult = new String(byteResult);
		logger.debug("조회결과: "+StringResult);
		return StringResult; 
	}
	
}
