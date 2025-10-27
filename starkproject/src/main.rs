use anyhow::Result;

// Winterfell imports (0.13.1)
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, Proof, TraceTable, TraceInfo, ProofOptions, verify, matrix::ColMatrix, 
    StarkDomain, DefaultConstraintEvaluator, DefaultTraceLde,
    Trace, DefaultConstraintCommitment, PartitionOptions,TracePolyTable, ConstraintCompositionCoefficients, AuxRandElements

};
use winterfell::{AcceptableOptions, BatchingMethod, CompositionPoly, CompositionPolyTrace, FieldExtension, Prover, TransitionConstraintDegree, VerifierError};
//use winterfell::math::fields::f128::BaseElement;

use winterfell::math::{FieldElement, ToElements};
use winterfell::math::fields::f64::BaseElement;

use winterfell::crypto::{hashers, DefaultRandomCoin, MerkleTree};

// ----------------- Domain data  -----------------
// const MALATTIE: [(u64, u64, [u64; 3]); 4] = [
//     (0, 3897, [3335, 2151, 3067]), // Cancro
//     (1, 2766, [4014, 3840, 4901]), // Cardiopatie
//     (2, 900, [2511, 2550, 0]),     // Diabete
//     (3, 40, [2411, 4506, 0]),      // Rene
// ];
// MALATTIE trasformate in BaseElement
const MALATTIE_BASE: [(BaseElement, BaseElement, [BaseElement; 3]); 4] = [
    (BaseElement::new(0), BaseElement::new(3897), [BaseElement::new(3335), BaseElement::new(2151), BaseElement::new(3067)]),
    (BaseElement::new(1), BaseElement::new(2766), [BaseElement::new(4014), BaseElement::new(3840), BaseElement::new(4901)]),
    (BaseElement::new(2), BaseElement::new(900),  [BaseElement::new(2511), BaseElement::new(2550), BaseElement::new(0)]),
    (BaseElement::new(3), BaseElement::new(40),   [BaseElement::new(2411), BaseElement::new(4506), BaseElement::new(0)]),
];

pub fn build_trace(inputs: &DiagnosiInputs) -> TraceTable<BaseElement> {
    let trace_width = 4;
    let trace_length = 8; // minimo 8

    let mut trace = TraceTable::new(trace_width, trace_length);

    trace.fill(
        |state| {
            // inizializza la prima riga con i valori di input
            state[0] = inputs.hash_diagnosi;
            state[1] = inputs.malattia_id;
            state[2] = inputs.sottocategoria_id;
            state[3] = BaseElement::ZERO;
        },
        |_, state| {
            // copia manualmente i valori della riga precedente e aggiunge 1 per differenziare
            state[0] = state[0] + BaseElement::new(1);
            state[1] = state[1] + BaseElement::new(1);
            state[2] = state[2] + BaseElement::new(1);
            state[3] = state[3] + BaseElement::new(1);
        },
    );

    trace
}

#[derive(Clone)]
pub struct DiagnosiInputs {
    pub hash_diagnosi: BaseElement,
    pub malattia_id: BaseElement,
    pub sottocategoria_id: BaseElement,
}



// --- AIR ---
pub struct DiagnosiAir {
    context: AirContext<BaseElement>,
    //pub_inputs: BaseElement,
}



impl Air for DiagnosiAir {
    type BaseField = BaseElement;
    type PublicInputs = ();


    fn new(trace_info: TraceInfo, pub_inputs: (), options: ProofOptions) -> Self {
        // our execution trace should have 4 column.
        assert_eq!(4, trace_info.width());

        let degrees = vec![TransitionConstraintDegree::new(1)];
        let context = AirContext::new(trace_info, degrees, 1, options);
        Self { context }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        // prendi i valori dal trace
        let idx: E = frame.current()[3];
        let hash_diag: E = frame.current()[0] - idx;
        let mal_id: E = frame.current()[1] - idx;
        let sottocat_id: E = frame.current()[2] - idx;

        //println!("hash_diag: {:?}, mal_id: {:?}, sottocat_id: {:?}", hash_diag, mal_id, sottocat_id);

        let mut is_valid: E = E::ONE;

        //controlla che le gli accoppiamenti hash, id e sottocategoria esistono
        for (id, hash, sottos) in MALATTIE_BASE.iter() {
            let id_e: E = (*id).into();
            let hash_e: E = (*hash).into();
            let sottocat_ids_e: [E; 3] = [sottos[0].into(), sottos[1].into(), sottos[2].into()];

            if mal_id == id_e && hash_diag == hash_e && sottocat_ids_e.contains(&sottocat_id) {
                is_valid = E::ZERO;
            }
        }

        result[0] = is_valid; //0 se valido
        //println!("constraint value: {:?}", result[0]);
    }


    //almeno una
    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        // Verifica che il primo indice sia 0
        vec![Assertion::single(3, 0, BaseElement::ZERO)]
    }

}


type H = hashers::Blake3_256<BaseElement>;


// ======= Esempio di struttura prover (adatta alla tua logica) =======
pub struct DiagnosiProver {
    pub options: ProofOptions,
}

impl DiagnosiProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

// ======= Implementazione del trait Prover =======
// Nota: gli alias/generics qui seguono l'esempio che hai fornito.
impl Prover for DiagnosiProver {
    type BaseField = BaseElement;
    type Air = DiagnosiAir; // la tua AIR già definita nel progetto
    type Trace = TraceTable<BaseElement>;

    // tipi "default" usati nell'esempio:
    type HashFn = H;
    type RandomCoin = DefaultRandomCoin<H>;

    type VC = MerkleTree<H>;

    // Trace LDE: default implementation (parametrizzato dall'hasher)
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, H, Self::VC>;


    // Aux random elements (for FRI/DEEP composition)
    //type AuxRandElements<E: FieldElement<BaseField = BaseElement>> = AuxRandElements<E>;

    // Constraint evaluator and commitment using defaults
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, DiagnosiAir, E>;

    // VC stands for "Verifier Commitments" (o similar) - lascia il tipo interno alla default
    //type VC = <DefaultConstraintCommitment<(), H, ()> as SomeDummy>::Placeholder; // <<=== PLACEHOLDER
    

    // Actual constraint commitment type (usa DefaultConstraintCommitment)
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, H, Self::VC>;


    // ====================================================
    // public inputs vuoto
    // ====================================================
    fn get_pub_inputs(&self, _trace: &Self::Trace) -> () {
        ()
    }


    // ====================================================
    // default trace LDE
    // ====================================================
    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    // ====================================================
    // default constraint evaluator
    // ====================================================
    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a DiagnosiAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    // ====================================================
    // default constraint commitment
    // ====================================================
    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}

fn main() -> Result<(), VerifierError> {
    let inputs = DiagnosiInputs {
        hash_diagnosi: BaseElement::new(40),
        malattia_id: BaseElement::new(3),
        sottocategoria_id: BaseElement::new(2411),
    };

    let trace = build_trace(&inputs);
    //let trace_info = trace.info();

    let options = ProofOptions::new(
        32, 8, 0,
        FieldExtension::None,
        8, 127,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );

    let prover = DiagnosiProver::new(options);

    let proof = prover.prove(trace).unwrap();

    let proof_bits=proof.to_bytes();

    println!("Proof: {:?}",proof_bits);

    let proofn = Proof::from_bytes(&proof_bits);
    let proofn = proofn.expect("Errore durante la deserializzazione del proof");

    // Verifica
    let min_opts = AcceptableOptions::MinConjecturedSecurity(63);
    let verify_res = verify::<DiagnosiAir,H,DefaultRandomCoin<H>,MerkleTree<H>>(proofn, (), &min_opts);
    println!("Verifica: {:?}", verify_res);

    Ok(())
}



