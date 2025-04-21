package es.gob.afirma.ios;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import es.gob.afirma.core.AOCancelledOperationException;
import es.gob.afirma.core.AOException;
import es.gob.afirma.signers.pades.AOPDFSigner;
import es.gob.afirma.signers.pades.IncorrectPageException;
import es.gob.afirma.signers.pades.InvalidPdfException;
import es.gob.afirma.signers.pades.InvalidSignaturePositionException;
import es.gob.afirma.signers.pades.PdfSignResult;
import es.gob.afirma.signers.pades.common.BadPdfPasswordException;
import es.gob.afirma.signers.pades.common.PdfExtraParams;
import es.gob.afirma.signers.pades.common.PdfFormModifiedException;
import es.gob.afirma.signers.pades.common.PdfHasUnregisteredSignaturesException;
import es.gob.afirma.signers.pades.common.PdfIsCertifiedException;
import es.gob.afirma.signers.pades.common.PdfIsPasswordProtectedException;
import es.gob.afirma.signers.pades.common.SuspectedPSAException;

public class PadesSignerWrapper {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	private final AOPDFSigner signer;

	public PadesSignerWrapper() {
		this.signer = new AOPDFSigner();
	}

	/**
	 * Firma un PDF en formato PAdES y devuelve el resultado de la operaci&oacute;n.
	 * @param inPdf Documento PDF que se desea firmar. 
	 * @param signAlgorithm Algoritmo de firma.
	 * @param key Clave privada de firma.
	 * @param certChain Cadena de certificaci&oacute;n del certificado de firma.
	 * @param xParams Propiedades de configuraci&oacute;n del formato.
	 * @return Resultado de la firma, que puede haber terminado bien o mal.
	 */
	public SignatureResult sign(final byte[] inPdf,
	        final String signAlgorithm,
	        final PrivateKey key,
	        final java.security.cert.Certificate[] certChain,
	        final Properties xParams) {

		byte[] pdfSignature;
		try {
			pdfSignature = this.signer.sign(inPdf, signAlgorithm, key, certChain, xParams);
		} catch (final Throwable e) {
			ErrorResult error = identifyError(e);
			return new SignatureResult(error.getError(), error.getMessage(), error.getSupportRetry());
		}
		return new SignatureResult(pdfSignature);
	}
	
	/**
	 * Firma un PDF en formato PAdES y devuelve el resultado de la operaci&oacute;n.
	 * @param inPdf Documento PDF que se desea firmar. 
	 * @param signAlgorithm Algoritmo de firma.
	 * @param key Clave privada de firma.
	 * @param certChain Cadena de certificaci&oacute;n del certificado de firma.
	 * @param xParams Propiedades de configuraci&oacute;n del formato.
	 * @return Resultado de la firma, que puede haber terminado bien o mal.
	 */
	@SuppressWarnings("static-method")
	public PresignResult presign(final byte[] inPdf,
	        final String signAlgorithm,
	        final java.security.cert.Certificate[] certChain,
	        final Properties xParams) {

		PresignResult preSignResult;

		try {
			final PdfSignResult result = PadesTrisigner.presign(inPdf, signAlgorithm, certChain, xParams);
			preSignResult = new PresignResult(result);
		} catch (final Throwable e) {
			ErrorResult error = identifyError(e);
			return new PresignResult(error.getError(), error.getMessage(), error.getSupportRetry());
		}

		return preSignResult;
	}
	
	/**
	 * Firma un PDF en formato PAdES y devuelve el resultado de la operaci&oacute;n.
	 * @param inPdf Documento PDF que se desea firmar. 
	 * @param signAlgorithm Algoritmo de firma.
	 * @param key Clave privada de firma.
	 * @param certChain Cadena de certificaci&oacute;n del certificado de firma.
	 * @param xParams Propiedades de configuraci&oacute;n del formato.
	 * @return Resultado de la firma, que puede haber terminado bien o mal.
	 */
	@SuppressWarnings("static-method")
	public SignatureResult postsign(final byte[] inPdf,
			PresignResult presignResult,
			byte[] pkcs1,
	        final String signAlgorithm,
	        final java.security.cert.Certificate[] certChain,
	        final Properties xParams) {
		
		byte[] result;
		try {
			result = PadesTrisigner.postsign(inPdf,
					presignResult.getPreSignature(), pkcs1, signAlgorithm, certChain, xParams);
		} catch (final Throwable e) {
			ErrorResult error = identifyError(e);
			return new SignatureResult(error.getError(), error.getMessage(), error.getSupportRetry());
		}

		return new SignatureResult(result);
	}
	
	private static ErrorResult identifyError(Throwable e) {

		if (e instanceof PdfIsPasswordProtectedException) {
			LOGGER.log(Level.SEVERE, "El PDF esta protegido por contrasena", e); //$NON-NLS-1$
			return new ErrorResult(SignatureError.PASSWORD_PROTECTED, e.getMessage());
		} else if (e instanceof BadPdfPasswordException) {
			LOGGER.log(Level.SEVERE, "La contrasena del PDF no es correcta", e); //$NON-NLS-1$
			return new ErrorResult(SignatureError.BAD_PASSWORD, "La contrasena del PDF no es correcta"); //$NON-NLS-1$
		} else if (e instanceof InvalidPdfException) {
			LOGGER.log(Level.SEVERE, "El documento no es un PDF soportado", e); //$NON-NLS-1$
			return new ErrorResult(SignatureError.INVALID_PDF, "El documento no es un PDF soportado"); //$NON-NLS-1$
		} else if (e instanceof IncorrectPageException) {
			LOGGER.log(Level.SEVERE, "Se selecciono una pagina no valida para la rubrica del documento", e); //$NON-NLS-1$
			return new ErrorResult(SignatureError.INVALID_PAGE, "Se selecciono una pagina no valida para la rubrica del documento"); //$NON-NLS-1$
		} else if (e instanceof InvalidSignaturePositionException) {
			LOGGER.log(Level.SEVERE, "Se selecciono una posicion no valida para la rubrica del documento", e); //$NON-NLS-1$
			return new ErrorResult(SignatureError.INVALID_RUBRIC_POSITION, "Se selecciono una posicion no valida para la rubrica del documento"); //$NON-NLS-1$
		} else if (e instanceof PdfFormModifiedException) {
			LOGGER.log(Level.WARNING, "Hay sospechas de que uno de los campos de formulario ha sido modificado despues de una firma anterior", e); //$NON-NLS-1$
			final SupportRetry retry = new SupportRetry(PdfExtraParams.ALLOW_SIGN_MODIFIED_FORM, Boolean.TRUE.toString());
			return new ErrorResult(SignatureError.FORM_MODIFIED, "Hay sospechas de que uno de los campos de formulario ha sido modificado despues de una firma anterior", retry); //$NON-NLS-1$
		} else if (e instanceof SuspectedPSAException) {
			LOGGER.log(Level.WARNING, "Hay sospechas de que el documento ha sido modificado despues de una firma anterior", e); //$NON-NLS-1$
			final SupportRetry retry = new SupportRetry(PdfExtraParams.ALLOW_SHADOW_ATTACK, Boolean.TRUE.toString());
			return new ErrorResult(SignatureError.SUSPECTED_PSA, "Hay sospechas de que el documento ha sido modificado despues de una firma anterior", retry); //$NON-NLS-1$
		} else if (e instanceof PdfHasUnregisteredSignaturesException) {
			LOGGER.log(Level.WARNING, "El documento tiene firmas anteriores sin registrar correctamente", e); //$NON-NLS-1$
			final SupportRetry retry = new SupportRetry(PdfExtraParams.ALLOW_COSIGNING_UNREGISTERED_SIGNATURES, Boolean.TRUE.toString());
			return new ErrorResult(SignatureError.UNREGISTER_SIGNATURES, "El documento tiene firmas anteriores sin registrar correctamente", retry); //$NON-NLS-1$
		} else if (e instanceof PdfIsCertifiedException) {
			LOGGER.log(Level.WARNING, "El documento esta certificado y una nueva firma puede invalidar las anteriores", e); //$NON-NLS-1$
			final SupportRetry retry = new SupportRetry(PdfExtraParams.ALLOW_COSIGNING_UNREGISTERED_SIGNATURES, Boolean.TRUE.toString());
			return new ErrorResult(SignatureError.CERTIFIED_DOCUMENT, "El documento esta certificado y una nueva firma puede invalidar las anteriores", retry); //$NON-NLS-1$
		} else if (e instanceof AOCancelledOperationException) {
			LOGGER.log(Level.WARNING, "Operacion cancelada por el usuario", e); //$NON-NLS-1$
			return new ErrorResult(SignatureError.CANCELLED, "Operacion cancelada por el usuario"); //$NON-NLS-1$
		} else if (e instanceof AOException) {
			LOGGER.log(Level.SEVERE, "Error desconocido durante la operacion: " + e.getMessage(), e); //$NON-NLS-1$
			return new ErrorResult(SignatureError.UNKNOWN, e.getMessage());
		} else if (e instanceof IOException) {
			LOGGER.log(Level.SEVERE, "Error en una operacion de lectura/escritura", e); //$NON-NLS-1$
			return new ErrorResult(SignatureError.INPUT_OUTPUT_ERROR, "Error en una operacion de lectura/escritura"); //$NON-NLS-1$
		} else {
			LOGGER.log(Level.SEVERE, "Error desconocido grave", e); //$NON-NLS-1$
			return new ErrorResult(SignatureError.UNKNOWN_SEVERE, "Error desconocido grave"); //$NON-NLS-1$
		}

	}
	
	/**
	 * Conjunto de codigo de error y mensaje asociado.
	 */
	private static class ErrorResult {
		
		private int error;
		private String message;
		private SupportRetry supportRetry;
		
		public ErrorResult(int error, String message) {
			this.error = error;
			this.message = message;
			this.supportRetry = null;
		}
		
		public ErrorResult(int error, String message, SupportRetry supportRetry) {
			this.error = error;
			this.message = message;
			this.supportRetry = supportRetry;
		}
		
		public int getError() {
			return this.error;
		}
		
		public String getMessage() {
			return this.message;
		}
		
		public SupportRetry getSupportRetry() {
			return this.supportRetry;
		}
	}
}
