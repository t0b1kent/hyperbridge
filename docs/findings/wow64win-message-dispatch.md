# Nine wow64win cases lost their dispatch

## Measured

October 4, 2026, original 32-bit text-window probe: NtUserInternalGetWindowText read "OK", while SendMessageW(WM_GETTEXT) left the output buffer unchanged and DefWindowProcW returned an invalid result. One retained probe finding and a corrected text-window observation are documented; the summary does not specify an independent run count for every case.

Source audit of our `message_call_32to64` modification found nine cases converting guest pointers and then breaking without NtUserMessageCall or a return: WM_SETTEXT, WM_GETTEXT, WM_GETTEXTLENGTH, WM_ASKCBFORMATNAME, WM_GETMINMAXINFO, WM_STYLECHANGING, WM_STYLECHANGED, WM_SIZING and WM_MOVING.

## Conclusion

Pointer conversion was present but dispatch was missing. The blank text symptom was not a font diagnosis. The common switch exit, not one message's buffer handling, was the fault class.

## Limits

Static coverage of nine cases is not a nine-message runtime matrix. The text observation does not establish the cause of unrelated startup crashes. Broader pointer-width and return-value coverage remains necessary.

## What would refute it

The corrected module still dropping the same text roundtrip, or a case whose converted pointer/return value fails a dedicated runtime check.

## Where it is fixed in our series

Wine patch **0090** restores dispatch/return for the family and was incorporated into the 1.0.8 Wine module. It belongs to the Wine series, not fex/patches. `-Wreturn-type` and a SETTEXT/GETTEXT roundtrip are useful admission checks for future thunk edits.
