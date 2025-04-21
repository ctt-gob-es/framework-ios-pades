package es.gob.afirma.ios;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.Properties;
import java.util.logging.Logger;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.signers.pades.InvalidPdfException;
import es.gob.afirma.signers.pades.PAdESTriPhaseSigner;
import es.gob.afirma.signers.pades.PdfSignResult;
import es.gob.afirma.signers.pades.PdfUtil;
import es.gob.afirma.signers.pades.common.PdfExtraParams;

public class PadesTrisigner {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$
	
	static PdfSignResult presign(final byte[] inPDF,
			           final String signAlgorithm,
			           final java.security.cert.Certificate[] certChain,
			           final Properties xParams) throws AOException,
			                                            IOException {

		final String algorithm = signAlgorithm != null ? signAlgorithm : AOSignConstants.DEFAULT_SIGN_ALGO;
        final Properties extraParams = getExtraParams(xParams);

        checkParams(algorithm, extraParams);

        final java.security.cert.Certificate[] certificateChain = Boolean.parseBoolean(extraParams.getProperty(PdfExtraParams.INCLUDE_ONLY_SIGNNING_CERTIFICATE, Boolean.FALSE.toString())) ?
    		new X509Certificate[] { (X509Certificate) certChain[0] } :
    			certChain;

    	final GregorianCalendar signTime = PdfUtil.getSignTime(extraParams.getProperty(PdfExtraParams.SIGN_TIME));

        final byte[] data = inPDF;

		// Prefirma
        final PdfSignResult pre;
        try {
			pre = PAdESTriPhaseSigner.preSign(
					algorithm,
				data,
				certificateChain,
				signTime,
				extraParams,
				true
			);
		}
        catch (final InvalidPdfException e) {
			throw e;
		}

        return pre;
    }
	
	private static Properties getExtraParams(final Properties extraParams) {
    	final Properties newExtraParams = extraParams != null ?
    			(Properties) extraParams.clone() : new Properties();

    	return newExtraParams;
    }
	
	private static void checkParams(final String algorithm, final Properties extraParams) {

    	if (algorithm.toUpperCase(Locale.US).startsWith("MD")) { //$NON-NLS-1$
    		throw new IllegalArgumentException("PAdES no permite huellas digitales MD2 o MD5 (Decision 130/2011 CE)"); //$NON-NLS-1$
    	}

    	final String profile = extraParams.getProperty(PdfExtraParams.PROFILE);

		// Comprobacion del perfil de firma con la configuracion establecida
		if (AOSignConstants.SIGN_PROFILE_BASELINE.equalsIgnoreCase(profile)) {
			if (AOSignConstants.isSHA1SignatureAlgorithm(algorithm)) {
				LOGGER.warning("El algoritmo '" + algorithm + "' no esta recomendado para su uso en las firmas baseline"); //$NON-NLS-1$ //$NON-NLS-2$
			}

			if (extraParams.containsKey(PdfExtraParams.SIGNATURE_SUBFILTER)) {
				LOGGER.warning("Se ignorara el valor establecido en el parametro '" + //$NON-NLS-1$
						PdfExtraParams.SIGNATURE_SUBFILTER +
						"' ya que en las firmas baseline el subfiltro siempre sera " + //$NON-NLS-1$
						AOSignConstants.PADES_SUBFILTER_BES);
				extraParams.remove(PdfExtraParams.SIGNATURE_SUBFILTER);
			}
		}

		// Las firmas BES no pueden declarar commitmentTypeIndications. Solo esta
		// permitido para las firmas EPES y B-Level.
		if (extraParams.containsKey(PdfExtraParams.COMMITMENT_TYPE_INDICATIONS)
				&& !AOSignConstants.SIGN_PROFILE_BASELINE.equalsIgnoreCase(profile)
				&& !extraParams.containsKey(PdfExtraParams.POLICY_IDENTIFIER)) {
			LOGGER.warning("Se ignoraran los commitment type indications establecidos por no estar permitidos en las firmas PAdES-EPES"); //$NON-NLS-1$
			extraParams.remove(PdfExtraParams.COMMITMENT_TYPE_INDICATIONS);
		}

		// Si se indico una politica de firma y una razon de firma, se omitira la
		// razon de firma
		if (extraParams.containsKey(PdfExtraParams.SIGN_REASON) &&
				extraParams.containsKey(PdfExtraParams.POLICY_IDENTIFIER)) {
				LOGGER.warning("Se ignorara la razon de firma establecida por haberse indicado una politica de firma"); //$NON-NLS-1$
				extraParams.remove(PdfExtraParams.SIGN_REASON);
		}

		// Si se declaran commintment type indications y una razon de firma,
		// solo se tendra en cuenta la razon de firma. El uso de la comprobacion
		// anterior y esta, permitiria usar politica de firma y  commitment
		// type indications simultaneamente
		if (extraParams.containsKey(PdfExtraParams.SIGN_REASON) &&
				extraParams.containsKey(PdfExtraParams.COMMITMENT_TYPE_INDICATIONS)) {
				LOGGER.warning("Se ignoraran los commitment type indications establecidos por haberse indicado una razon de firma"); //$NON-NLS-1$
				extraParams.remove(PdfExtraParams.COMMITMENT_TYPE_INDICATIONS);
		}
    }
	

    static byte[] postsign(final byte[] inPDF,
    		final PdfSignResult pre,
    		final byte[] interSign,
    		final String signAlgorithm,
    		final java.security.cert.Certificate[] certChain,
    		final Properties xParams) throws AOException, IOException {

    	final String algorithm = signAlgorithm != null ? signAlgorithm : AOSignConstants.DEFAULT_SIGN_ALGO;
    	final Properties extraParams = getExtraParams(xParams);

    	checkParams(algorithm, extraParams);

    	final java.security.cert.Certificate[] certificateChain = Boolean.parseBoolean(extraParams.getProperty(PdfExtraParams.INCLUDE_ONLY_SIGNNING_CERTIFICATE, Boolean.FALSE.toString())) ?
    			new X509Certificate[] { (X509Certificate) certChain[0] } :
    				certChain;

    	final byte[] data = inPDF;

    	try {
    		return PAdESTriPhaseSigner.postSign(
    				algorithm,
    				data,
    				certificateChain,
    				interSign,
    				pre,
    				null,
    				null,
    				true
    				);
    	}
    	catch (final NoSuchAlgorithmException e) {
    		throw new AOException("Error el en algoritmo de firma: " + e, e); //$NON-NLS-1$
    	}

    }
}
