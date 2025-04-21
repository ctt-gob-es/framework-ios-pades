package es.gob.afirma.test.pades;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.Signature;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.ios.PadesSignerWrapper;
import es.gob.afirma.ios.PresignResult;
import es.gob.afirma.ios.SignatureResult;

public class TriSignerTest {

	private static final String ALGORITHM_SHA256WITHRSA = "SHA256withRSA"; //$NON-NLS-1$

	private final static String TEST_FILE = "TEST_PDF.pdf"; //$NON-NLS-1$

	private final static String CERT_PATH = "ANF_PF_Activo.pfx"; //$NON-NLS-1$
	private final static String CERT_PASS = "12341234"; //$NON-NLS-1$
	private final static String CERT_ALIAS = "anf usuario activo"; //$NON-NLS-1$
	
	private PrivateKeyEntry pke = null;
	private byte[] data = null;
	
	@Before
	public void loadKeys() {
		
		if (this.pke == null) {
			try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
				final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
				ks.load(is, CERT_PASS.toCharArray());
				this.pke = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS, new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));
			}
			catch (Exception e) {
				Assert.fail("Fallo del test: No se pudo cargar la clave de firma: " + e); //$NON-NLS-1$
			}
		}
	}
	
	@Before
	public void loadData() {
		
		if (this.data == null) {
			try (InputStream is = ClassLoader.getSystemResourceAsStream(TEST_FILE)) {
				this.data = AOUtil.getDataFromInputStream(is);
			}
			catch (Exception e) {
				Assert.fail("Fallo del test: No se pudieron cargar los datos: " + e); //$NON-NLS-1$
			}
		}
	}
	
	/**
	 * Ejemplo de firma completa compuesta de prefirma, firma y postfirma.
	 */
	@Test
	public void sign() {
		
		PadesSignerWrapper signer = new PadesSignerWrapper();
		
		// Prefirma
		PresignResult presign = signer.presign(this.data, ALGORITHM_SHA256WITHRSA, this.pke.getCertificateChain(), null);
		if (presign.isError()) {
			Assert.fail("Fallo la prefirma: " + presign.getErrorMessage()); //$NON-NLS-1$
		}
		
		byte[] pre = presign.getPreSignature().getSign();

		// Firma
		byte[] pkcs1;
		try {
			Signature signature = Signature.getInstance(ALGORITHM_SHA256WITHRSA);
			signature.initSign(this.pke.getPrivateKey());
			signature.update(pre);
			pkcs1 = signature.sign();
		}
		catch (Exception e) {
			Assert.fail("Fallo la firma PKCS1: " + e); //$NON-NLS-1$
			return;
		}
		
		// Postfirma
		SignatureResult signResult = signer.postsign(this.data, presign, pkcs1, ALGORITHM_SHA256WITHRSA, this.pke.getCertificateChain(), null);
		if (signResult.isError()) {
			Assert.fail("Fallo la postfirma: " + signResult.getErrorMessage()); //$NON-NLS-1$
		}
	}
}
