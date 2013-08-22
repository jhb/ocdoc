Proposals
=========

Payment info
------------

Alice might not be able to send coins directly to Bobs client. Instead she stores the 'send coin' message somewhere, and informs bob client about the location.

.. seqdiag::

    seqdiag {
        Alice; Bob; Storage;
        Alice -> Storage [label='put coins (oob)',leftnote='send coins:\n---\nsubject\ncoins'];
        Alice <-- Storage;
        
        Alice -> Bob [label='transfer info (oob)',
                      leftnote='payment info:
                                ---
                                subject
                                storage uri
                                amount'];
        Alice <-- Bob;
        
        Bob -> Storage [label='fetch coins (oob)'];
        Bob <- Storage;

    }


Payment request
---------------

This is basically a payment info reversed. Bob wants some coins from Alice, and tells here where to put the coins (and checks regulary if they are there):

.. seqdiag::

    seqdiag {
        Alice <- Bob [label='transfer request (oob)',
                       rightnote='payment request:
                                  ---
                                  subject
                                  target uri
                                  amount'];
        Alice --> Bob;
        Alice -> Target [label='put coins (oob)',leftnote='send coins:\n---\nsubject\ncoins'];
        Alice <-- Target;
        Bob -> Target [label='fetch coins (oob)'];
        Bob <- Target;

    }
