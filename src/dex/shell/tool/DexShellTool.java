package dex.shell.tool;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Adler32;

public class DexShellTool {
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			File payloadSrcFile = new File("E:/apkshell/payload.apk");
			File unShellDexFile = new File("E:/apkshell/unshell.dex");
			byte[] payloadArray = encrpt(readFileBytes(payloadSrcFile));
			byte[] unShellDexArray = readFileBytes(unShellDexFile);
			int payloadLen = payloadArray.length;
			int unShellDexLen = unShellDexArray.length;
			int totalLen = payloadLen + unShellDexLen + 4;
			byte[] newdex = new byte[totalLen];
			// 添加解壳代码
			System.arraycopy(unShellDexArray, 0, newdex, 0, unShellDexLen);
			// 添加加密后的解壳数据
			System.arraycopy(payloadArray, 0, newdex, unShellDexLen, payloadLen);
			// 添加paylaod.apk长度
			System.arraycopy(intToByte(payloadLen), 0, newdex, totalLen - 4, 4);
			// 修改DEX file size文件头
			fixFileSizeHeader(newdex);
			// 修改DEX SHA1 文件头
			fixSHA1Header(newdex);
			// 修改DEX CheckSum文件头
			fixCheckSumHeader(newdex);

			String str = "E:/apkshell/classes.dex";
			File file = new File(str);
			if (!file.exists()) {
				file.createNewFile();
			}
			FileOutputStream localFileOutputStream = new FileOutputStream(str);
			localFileOutputStream.write(newdex);
			localFileOutputStream.flush();
			localFileOutputStream.close();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// 直接返回数据，读者可以添加自己加密方法
	private static byte[] encrpt(byte[] srcdata) {
		return srcdata;
	}

	private static void fixCheckSumHeader(byte[] dexBytes) {
		Adler32 adler = new Adler32();
		adler.update(dexBytes, 12, dexBytes.length - 12);
		long value = adler.getValue();
		int va = (int) value;
		byte[] newcs = intToByte(va);
		byte[] recs = new byte[4];
		for (int i = 0; i < 4; i++) {
			recs[i] = newcs[newcs.length - 1 - i];
			System.out.println(Integer.toHexString(newcs[i]));
		}
		System.arraycopy(recs, 0, dexBytes, 8, 4);
		System.out.println(Long.toHexString(value));
		System.out.println();
	}

	public static byte[] intToByte(int number) {
		byte[] b = new byte[4];
		for (int i = 3; i >= 0; i--) {
			b[i] = (byte) (number % 256);
			// 右移1字节
			number >>= 8;
		}
		return b;
	}

	private static void fixSHA1Header(byte[] dexBytes) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(dexBytes, 32, dexBytes.length - 32);
		byte[] newdt = md.digest();
		System.arraycopy(newdt, 0, dexBytes, 12, 20);
		String hexstr = "";
		for (int i = 0; i < newdt.length; i++) {
			hexstr += Integer.toString((newdt[i] & 0xff) + 0x100, 16).substring(1);
		}
		System.out.println(hexstr);
	}

	private static void fixFileSizeHeader(byte[] dexBytes) {

		byte[] newfs = intToByte(dexBytes.length);
		System.out.println(Integer.toHexString(dexBytes.length));
		byte[] refs = new byte[4];
		for (int i = 0; i < 4; i++) {
			refs[i] = newfs[newfs.length - 1 - i];
			System.out.println(Integer.toHexString(newfs[i]));
		}
		System.arraycopy(refs, 0, dexBytes, 32, 4);
	}

	private static byte[] readFileBytes(File file) throws IOException {
		byte[] arrayOfByte = new byte[1024];
		ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
		FileInputStream fis = new FileInputStream(file);
		while (true) {
			int i = fis.read(arrayOfByte);
			if (i != -1) {
				localByteArrayOutputStream.write(arrayOfByte, 0, i);
			} else {
				fis.close();
				return localByteArrayOutputStream.toByteArray();
			}
		}
	}
}