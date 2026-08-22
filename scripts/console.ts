const ESC = String.fromCharCode(27);
const noColor = process.env['NO_COLOR'] !== undefined;

/**
 * Colour, honouring NO_COLOR.
 *
 * Shared by the adversarial suite and the recovery harness so their reports
 * look like one product rather than two scripts that grew separately -- these
 * are the artifacts a design partner's security reviewer reads.
 */
const paint = (code: string, text: string) => (noColor ? text : `${ESC}[${code}m${text}${ESC}[0m`);
export const bold = (t: string) => paint('1', t);
export const green = (t: string) => paint('32', t);
export const red = (t: string) => paint('31', t);
export const yellow = (t: string) => paint('33', t);
export const dim = (t: string) => paint('2', t);
