package es.gob.afirma.ios;

import es.gob.afirma.signers.pades.PdfSignResult;

/**
 * Resultado de una operaci&oacute;n de firma PAdES.
 */
public class PresignResult {

	private final PdfSignResult preSignature;

	private final String errorMessage;

	private final int errorCode;

	private final SupportRetry retry;

	/**
	 * Resultado correcto de una operaci&oacute;n de firma PAdES.
	 * @param padesSignature
	 */
	public PresignResult(final PdfSignResult preSignature) {
		this.preSignature = preSignature;
		this.errorMessage = null;
		this.errorCode = -1;
		this.retry = null;
	}

	/**
	 * Resultado de error de una operaci&oacute;n de firma PAdES.
	 * @param errorCode C&oacute;digo de error.
	 * @param errorMessage Mensaje de error.
	 */
	public PresignResult(final int errorCode, final String errorMessage) {
		this(errorCode, errorMessage, null);
	}

	/**
	 * Resultado de error de una operaci&oacute;n de firma PAdES.
	 * @param errorCode C&oacute;digo de error.
	 * @param errorMessage Mensaje de error.
	 */
	public PresignResult(final int errorCode, final String errorMessage, final SupportRetry retry) {
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
		this.retry = retry;
		this.preSignature = null;
	}

	/**
	 * Recupera la firma PAdES generada.
	 * @return La firma o {@code null} si no finaliz&oacute; correctamente.
	 */
	public PdfSignResult getPreSignature() {
		return this.preSignature;
	}

	/**
	 * Identifica si la operaci&oacute;n fall&oacute;.
	 * @return {@code true} si el resultado es un error, {@code false} en caso contrario.
	 */
	public boolean isError() {
		return this.errorCode != -1;
	}

	/**
	 * Recupera el mensaje de error.
	 * @return Mensaje de error o {@code null} si no ocurri&oacute; ning&uacute;n error.
	 */
	public String getErrorMessage() {
		return this.errorMessage;
	}

	/**
	 * Recupera el c&oacute;digo de error.
	 * @return C&oacute;digo de error o {@code -1} si no ocurri&oacute; ning&uacute;n error.
	 */
	public int getErrorCode() {
		return this.errorCode;
	}

	/**
	 * Recupera la informaci&oacute;n para el reintento de la operaci&oacute;n.
	 * @return Informaci&oacute;n para el reintento de la operaci&oacute;n o {@code null} si no se defini&oacute;.
	 */
	public SupportRetry getRetry() {
		return this.retry;
	}

	/**
	 * Indica si se ha definido como reintentar la operaci&oacute;n para completarla correctamente.
	 * @return
	 */
	public boolean canRetry() {
		return this.retry != null;
	}
}
