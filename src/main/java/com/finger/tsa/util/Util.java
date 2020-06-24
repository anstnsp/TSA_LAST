package com.finger.tsa.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Util {

	private static final Logger logger = LoggerFactory.getLogger(Util.class);
	
	/**
	 * 파일을 바이너리 스트링으로 변경
	 *
	 * @param file
	 * @return String 
	 * @throws IOException 
	 */
	public static String fileToBinary(File file) throws IOException {
	    String out = new String();
	    FileInputStream fis = null;
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	 
	    try {
	        fis = new FileInputStream(file); //파일객체를 FileInputStream으로 생성.
	    } catch (FileNotFoundException e) {
	        logger.error("Exception position : FileUtil(FileNotFound) - fileToString(File file)");
	    }
	 
	    int len = 0;
	    byte[] buf = new byte[1024];
	    try {
	        while ((len = fis.read(buf)) != -1) { //FileInputStream을  ByteArrayOutputStream에 쓴다.
	            baos.write(buf, 0, len);
	        }
	 
	        byte[] fileArray = baos.toByteArray(); //ByteArrayOutputStream 를 ByteArray 로 캐스팅한다
	        out = new String(base64Enc(fileArray));  //캐스팅 된 ByteArray를 Base64 로 인코딩한 후 String 로 캐스팅한다.

	    } catch (IOException e) {
	        logger.error("Exception position : FileUtil(IOException) - fileToString(File file)");
	    } finally {
	    	if(fis != null) try { fis.close();} catch(IOException e) { 
	    		logger.error("Exception position : FileUtil(IOException) - fileToString(File file)"); 
	    		throw e;
	    	}
	    	if(baos != null) try { baos.close();} catch(IOException e) { 
	    		logger.error("Exception position : FileUtil(IOException) - fileToString(File file)"); 
	    		throw e;
	    	}
	    }
	 
	    return out;
	}
	
	/**
	 * 
	 * @param pdf파일을 바이너리스트링으로 변환한 값
	 * @return pdf파일을 바이너리스트링으로 변환한 값을 SHA-256으로 해쉬한 값  
	 * @throws NoSuchAlgorithmException
	 */
	public static String getHashFromString(String StringFromPdf) throws NoSuchAlgorithmException {
		//최초받은 바이너리스트링 값을 바이트배열로 바꿈. 
		byte[] byteArr = binaryStringToByteArray(StringFromPdf);
		
		MessageDigest hashSum = MessageDigest.getInstance("SHA-256");
		hashSum.update(byteArr);
		String hashedStringFromPdf = Base64.encodeBase64String(hashSum.digest()); //해쉬생성 후 베이스64스트링 인코딩 .
		return hashedStringFromPdf;
	}

	/**
	 * 바이너리 스트링을 파일로 변환
	 *
	 * @param binaryFile
	 * @param filePath
	 * @param fileName 
	 * @return
	 * @throws IOException 
	 */
	public static File binaryToFile(String binaryFile, String filePath, String fileName) throws IOException {
		
	    if ((binaryFile == null || "".equals(binaryFile)) || (filePath == null || "".equals(filePath))
	            || (fileName == null || "".equals(fileName))) { return null; }
	 
	    FileOutputStream fos = null;
	 
	    File fileDir = new File(filePath);  //파일을 저장할 경로가 없으면 만들어 준다.
	    if (!fileDir.exists()) {
	        fileDir.mkdirs();
	    }
	 
	    File destFile = new File(filePath + fileName); //파일경로와 파일명을 합치고 파일 객체를 만든다.
	 
	    byte[] buff = binaryFile.getBytes();  //Base64로 인코딩된 바이너리 스트링을 Base64로 디코딩 한 후 String으로 캐스팅한다. 
	    String toStr = new String(buff);
	    byte[] b64dec = base64Dec(toStr);
	 
	    try {
	        fos = new FileOutputStream(destFile);  //바이너리 스트링을 생성한 파일객체에 써서 파일로 만든다. 
	        fos.write(b64dec);
	        fos.close();
	    } catch (IOException e) {
	        System.out.println("Exception position : FileUtil(IOException) - binaryToFile(String binaryFile, String filePath, String fileName)");
	    } finally {
	    	if(fos != null) try { fos.close();} catch(IOException e) { 
	    		logger.error("Exception position : FileUtil(IOException) - binaryToFile(String binaryFile, String filePath, String fileName)"); 
	    		throw e;
	    	}
	    }
	 
	    return destFile;
	}

	public static byte[] base64Enc(byte[] buffer) {
	    return Base64.encodeBase64(buffer);

	}

	public static byte[] base64Dec(String binaryString) {
		return Base64.decodeBase64(binaryString);
	}

	public static String encodeBase64String(byte[] buffer) {
		return Base64.encodeBase64String(buffer);
	}

    /**
     * 바이너리 스트링을 바이트배열로 변환
     * 
     * @param s
     * @return
     */
    public static byte[] binaryStringToByteArray(String s) {
        int count = s.length() / 8;
        byte[] b = new byte[count];
        for (int i = 1; i < count; ++i) {
            String t = s.substring((i - 1) * 8, i * 8);
            b[i - 1] = binaryStringToByte(t);
        }
        return b;
    }

    /**
     * 바이너리 스트링을 바이트로 변환
     * 
     * @param s
     * @return
     */
    public static byte binaryStringToByte(String s) {
        byte ret = 0, total = 0;
        for (int i = 0; i < 8; ++i) {
            ret = (s.charAt(7 - i) == '1') ? (byte) (1 << i) : 0;
            total = (byte) (ret | total);
        }
        return total;
    }
    
    /**
     * 바이너리 바이트 배열을 스트링으로 변환
     * 
     * @param b
     * @return
     */
    public static String byteArrayToBinaryString(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; ++i) {
            sb.append(byteToBinaryString(b[i]));
        }
        return sb.toString();
    }

    /**
     * 바이너리 바이트를 스트링으로 변환
     * 
     * @param n
     * @return
     */
    public static String byteToBinaryString(byte n) {
        StringBuilder sb = new StringBuilder("00000000");
        for (int bit = 0; bit < 8; bit++) {
            if (((n >> bit) & 1) > 0) {
                sb.setCharAt(7 - bit, '1');
            }
        }
        return sb.toString();
    }
	/**
	 *  TimeStampToken 객체로 변경해주는 함수
	 * @param timeStampToken
	 * @return TimeStampToken
	 * @throws CMSException
	 * @throws TSPException
	 * @throws IOException
	 */
	public static TimeStampToken byteToTimeStamp(byte[] timeStampToken) throws CMSException, TSPException, IOException {
		logger.debug("byteToTimeStamp START !!");
		try {
			CMSSignedData signedToken = new CMSSignedData(timeStampToken);
			return new TimeStampToken(signedToken);
		} catch (CMSException |TSPException | IOException e) {
			logger.error("byteToTimeStamp failed check timeStampToken: {}", e.getMessage());
			throw e;
		} 

	}
	/**
	 * 파라미터로 받은 경로로 개인키파일을 읽어 개인키 obj형태로 만드는 함수
	 * 
	 * @param path 개인키 인증서 경로
	 * @return PrivateKey
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws Exception
	 */
	public static PrivateKey getPrivateKey(String path)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NullPointerException {
		logger.debug("getPrivateKey START !!");
		try {
			logger.debug("path : {}", path);
			if (path == null || path.isEmpty()) {
				throw new NullPointerException("null or empty!! check parameter !!");
			}

			byte[] keyBytes = Files.readAllBytes(Paths.get(path));
			logger.debug("getPrivateKey keyBytes : {} ", keyBytes.length);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
		} catch (IOException e) {
			logger.error("privatekey File read Failed \ncheck permission and path !! :  {}", e.getMessage());
			throw e;
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			logger.error("privatekey File read Failed \nJCE provider check !! :  {}", e.getMessage());
			throw e;
		}

	}

	/**
	 * 파라미터로 받은 경로로 공개키 파일을 읽어 공개키 키 obj형태로 만드는 함수
	 * 
	 * @param path 공개키 인증서 경로
	 * @return X509Certificate
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws CertificateException
	 */
	public static X509Certificate getPublicKey(String path) throws CertificateException, IOException, NullPointerException {
		logger.debug("getPublicKey START !!");
		FileInputStream is = null;
		try {
			logger.debug("path : {}", path);
			if (path == null || path.isEmpty()) {
				throw new NullPointerException("null or empty!! check parameter !!");
			}
			is = new FileInputStream(new File(path));
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) cf.generateCertificate(is);
		} catch (IOException e) {
			logger.error("publicKey File read Failed \ncheck permission and path !! :  {}", e.getMessage());
			throw e;
		} catch (CertificateException e) {
			logger.error("{} is not Certificate check File!! :  {}", path, e.getMessage());
			throw e;
		} finally {
			try {
				is.close();
			} catch (IOException e) {
				logger.error("FileInputStream Close Failed check system and jdk :{} ", e.getMessage());
				throw e;
			}
		}

	}
}
