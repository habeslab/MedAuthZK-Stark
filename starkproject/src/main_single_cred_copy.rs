extern crate winterfell;

use std::time::{Duration, Instant};

use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, Proof, TraceTable, TraceInfo, ProofOptions,
    verify, matrix::ColMatrix, StarkDomain, DefaultConstraintEvaluator, DefaultTraceLde,
    DefaultConstraintCommitment, PartitionOptions, TracePolyTable,
    ConstraintCompositionCoefficients, AuxRandElements, AcceptableOptions, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, FieldExtension, Prover, TransitionConstraintDegree,
    VerifierError,
};

use winterfell::math::{FieldElement, ToElements};
use winterfell::math::fields::f64::BaseElement;
use winterfell::crypto::{hashers, DefaultRandomCoin, MerkleTree};

// ================================================================================================
// Domain data
// ================================================================================================
//
// Ogni riga rappresenta:
// (malattia_id, hash_diagnosi, [sottocategorie valide])
//
// La policy in questo prototipo è modellata come:
// policy_id == sottocategoria_id
//
// Quindi il verifier chiede una policy/trattamento d_i,
// e il prover dimostra in ZK che la propria sottocategoria privata coincide con d_i
// ed è coerente con malattia_id e hash_diagnosi.

const NUM_DISEASES: usize = 4;
const NUM_SELECTORS: usize = NUM_DISEASES;

const MALATTIE_BASE: [(BaseElement, BaseElement, [BaseElement; 3]); NUM_DISEASES] = [
    (
        BaseElement::new(0),
        BaseElement::new(3897),
        [
            BaseElement::new(3335),
            BaseElement::new(2151),
            BaseElement::new(3067),
        ],
    ),
    (
        BaseElement::new(1),
        BaseElement::new(2766),
        [
            BaseElement::new(4014),
            BaseElement::new(3840),
            BaseElement::new(4901),
        ],
    ),
    (
        BaseElement::new(2),
        BaseElement::new(900),
        [
            BaseElement::new(2511),
            BaseElement::new(2550),
            BaseElement::new(0),
        ],
    ),
    (
        BaseElement::new(3),
        BaseElement::new(40),
        [
            BaseElement::new(2411),
            BaseElement::new(4506),
            BaseElement::new(0),
        ],
    ),
];

// ================================================================================================
// Trace layout
// ================================================================================================
//
// 0  hash_diagnosi        private witness
// 1  malattia_id          private witness
// 2  sottocategoria_id    private witness
// 3  commitment C         public input
// 4  policy_id            public input
// 5  nonce                public input
// 6  session_binding      public input
// 7  selector b0          private witness
// 8  selector b1          private witness
// 9  selector b2          private witness
// 10 selector b3          private witness
const COL_HASH: usize = 0;
const COL_MAL: usize = 1;
const COL_SOTT: usize = 2;
const COL_COMMITMENT: usize = 3;
const COL_POLICY: usize = 4;
const COL_NONCE: usize = 5;
const COL_SESSION_BINDING: usize = 6;

// Table row currently scanned
const COL_TABLE_ID: usize = 7;
const COL_TABLE_HASH: usize = 8;
const COL_TABLE_S0: usize = 9;
const COL_TABLE_S1: usize = 10;
const COL_TABLE_S2: usize = 11;

// Private dynamic witness
const COL_MATCH: usize = 12;
const COL_ACC: usize = 13;

const TRACE_WIDTH: usize = 14;
const TRACE_LENGTH: usize = 8;

// Constraints:
// 1. carry public/private claim columns: 7
// 2. match flag booleanity: 1
// 3. selected row must match disease id: 1
// 4. selected row must match disease hash: 1
// 5. selected row must match one of the three subcategories: 1
// 6. policy_id == sottocategoria_id: 1
// 7. commitment opening: 1
// 8. session binding: 1
// 9. accumulator transition: 1
const NUM_CONSTRAINTS: usize = 15;

const NUM_ASSERTIONS: usize = 4 + 5 * TRACE_LENGTH + 2;

// ================================================================================================
// Public inputs
// ================================================================================================

#[derive(Clone, Debug)]
pub struct DiagnosiPublicInputs {
    pub commitment: BaseElement,
    pub policy_id: BaseElement,
    pub nonce: BaseElement,
    pub session_binding: BaseElement,
}

impl ToElements<BaseElement> for DiagnosiPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.commitment,
            self.policy_id,
            self.nonce,
            self.session_binding,
        ]
    }
}

// ================================================================================================
// Private inputs
// ================================================================================================

#[derive(Clone)]
pub struct DiagnosiInputs {
    pub hash_diagnosi: BaseElement,
    pub malattia_id: BaseElement,
    pub sottocategoria_id: BaseElement,

    // Nel prototipo policy_id coincide con il trattamento/sottocategoria richiesta.
    // È pubblico perché il verifier sa quale policy sta chiedendo.
    pub policy_id: BaseElement,

    // Nonce pubblico generato dal verifier.
    pub nonce: BaseElement,
}

// ================================================================================================
// Demo commitment and session binding
// ================================================================================================
//
// Queste funzioni sono AIR-friendly ma NON crittografiche.
// Servono per modellare il circuito corretto.
//
// Nel paper puoi dire:
// "The prototype uses an AIR-compatible commitment function to model commitment opening;
// replacing it with a full cryptographic hash AIR is left as an implementation extension."
//
// Se vuoi essere più forte nel paper, devi sostituire queste funzioni con una vera hash
// implementata in AIR.

fn demo_commitment_base(
    hash: BaseElement,
    mal: BaseElement,
    sott: BaseElement,
) -> BaseElement {
    hash * BaseElement::new(17)
        + mal * BaseElement::new(31)
        + sott * BaseElement::new(43)
        + BaseElement::new(12_345)
}

fn demo_commitment<E: FieldElement<BaseField = BaseElement>>(
    hash: E,
    mal: E,
    sott: E,
) -> E {
    hash * E::from(BaseElement::new(17))
        + mal * E::from(BaseElement::new(31))
        + sott * E::from(BaseElement::new(43))
        + E::from(BaseElement::new(12_345))
}

fn demo_session_binding_base(
    commitment: BaseElement,
    policy_id: BaseElement,
    nonce: BaseElement,
) -> BaseElement {
    commitment * BaseElement::new(101)
        + policy_id * BaseElement::new(103)
        + nonce * BaseElement::new(107)
        + BaseElement::new(99_999)
}

fn demo_session_binding<E: FieldElement<BaseField = BaseElement>>(
    commitment: E,
    policy_id: E,
    nonce: E,
) -> E {
    commitment * E::from(BaseElement::new(101))
        + policy_id * E::from(BaseElement::new(103))
        + nonce * E::from(BaseElement::new(107))
        + E::from(BaseElement::new(99_999))
}

fn build_public_inputs(inputs: &DiagnosiInputs) -> DiagnosiPublicInputs {
    let commitment = demo_commitment_base(
        inputs.hash_diagnosi,
        inputs.malattia_id,
        inputs.sottocategoria_id,
    );

    let session_binding =
        demo_session_binding_base(commitment, inputs.policy_id, inputs.nonce);

    DiagnosiPublicInputs {
        commitment,
        policy_id: inputs.policy_id,
        nonce: inputs.nonce,
        session_binding,
    }
}

// ================================================================================================
// Selector computation
// ================================================================================================
//
// Trova la riga della tabella che corrisponde a:
//
// malattia_id == id_i
// hash_diagnosi == hash_i
// sottocategoria_id è una delle tre sottocategorie della riga
//
// Inoltre, in questo prototipo:
// policy_id == sottocategoria_id

fn find_matching_disease(inputs: &DiagnosiInputs) -> Option<usize> {
    MALATTIE_BASE.iter().position(|&(id, hash, sottos)| {
        let sott_matches =
            inputs.sottocategoria_id == sottos[0]
                || inputs.sottocategoria_id == sottos[1]
                || inputs.sottocategoria_id == sottos[2];

        inputs.malattia_id == id
            && inputs.hash_diagnosi == hash
            && sott_matches
            && inputs.policy_id == inputs.sottocategoria_id
    })
}

// ================================================================================================
// Trace builder
// ================================================================================================

pub fn build_trace(inputs: &DiagnosiInputs) -> TraceTable<BaseElement> {
    let public_inputs = build_public_inputs(inputs);

    let selected_idx = find_matching_disease(inputs)
        .expect("Input non valido: nessuna riga di MALATTIE_BASE corrisponde ai claim forniti");

    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);

    trace.fill(
        |state| {
            fill_row(0, state, inputs, &public_inputs, selected_idx);
        },
        |step, state| {
            fill_row(step + 1, state, inputs, &public_inputs, selected_idx);
        },
    );

    trace
}

fn fill_row(
    row: usize,
    state: &mut [BaseElement],
    inputs: &DiagnosiInputs,
    public_inputs: &DiagnosiPublicInputs,
    selected_idx: usize,
) {
    // Private claims: constant across the trace
    state[COL_HASH] = inputs.hash_diagnosi;
    state[COL_MAL] = inputs.malattia_id;
    state[COL_SOTT] = inputs.sottocategoria_id;

    // Public statement: constant across the trace
    state[COL_COMMITMENT] = public_inputs.commitment;
    state[COL_POLICY] = public_inputs.policy_id;
    state[COL_NONCE] = public_inputs.nonce;
    state[COL_SESSION_BINDING] = public_inputs.session_binding;

    // Current table row
    let (id, hash, sottos) = table_row(row);

    state[COL_TABLE_ID] = id;
    state[COL_TABLE_HASH] = hash;
    state[COL_TABLE_S0] = sottos[0];
    state[COL_TABLE_S1] = sottos[1];
    state[COL_TABLE_S2] = sottos[2];

    // match_flag = 1 only on the selected disease row
    state[COL_MATCH] = if row == selected_idx {
        BaseElement::ONE
    } else {
        BaseElement::ZERO
    };

    // acc[row] = number of matches seen before this row
    //
    // If selected_idx = 3:
    // row 0 acc = 0
    // row 1 acc = 0
    // row 2 acc = 0
    // row 3 acc = 0
    // row 4 acc = 1
    // ...
    state[COL_ACC] = if row > selected_idx {
        BaseElement::ONE
    } else {
        BaseElement::ZERO
    };
}

fn table_row(row: usize) -> (BaseElement, BaseElement, [BaseElement; 3]) {
    if row < NUM_DISEASES {
        MALATTIE_BASE[row]
    } else {
        (
            BaseElement::ZERO,
            BaseElement::ZERO,
            [
                BaseElement::ZERO,
                BaseElement::ZERO,
                BaseElement::ZERO,
            ],
        )
    }
}

// ================================================================================================
// AIR
// ================================================================================================

pub struct DiagnosiAir {
    context: AirContext<BaseElement>,
    pub_inputs: DiagnosiPublicInputs,
}

impl Air for DiagnosiAir {
    type BaseField = BaseElement;
    type PublicInputs = DiagnosiPublicInputs;

   fn new(
    trace_info: TraceInfo,
    pub_inputs: DiagnosiPublicInputs,
    options: ProofOptions,
) -> Self {
    assert_eq!(TRACE_WIDTH, trace_info.width());

    let degrees = vec![
        // 1. Carry constraints for claim/public columns
        TransitionConstraintDegree::new(1), // hash
        TransitionConstraintDegree::new(1), // mal
        TransitionConstraintDegree::new(1), // sott
        TransitionConstraintDegree::new(1), // commitment
        TransitionConstraintDegree::new(1), // policy
        TransitionConstraintDegree::new(1), // nonce
        TransitionConstraintDegree::new(1), // session binding

        // 2. match flag booleanity: b * (b - 1)
        TransitionConstraintDegree::new(2),

        // 3. selected row disease id match: b * (mal - table_id)
        TransitionConstraintDegree::new(2),

        // 4. selected row hash match: b * (hash - table_hash)
        TransitionConstraintDegree::new(2),

        // 5. selected row subcategory membership:
        // b * (sott - s0)(sott - s1)(sott - s2)
        TransitionConstraintDegree::new(4),

        // 6. policy check
        TransitionConstraintDegree::new(1),

        // 7. commitment opening
        TransitionConstraintDegree::new(1),

        // 8. session binding
        TransitionConstraintDegree::new(1),

        // 9. accumulator transition
        TransitionConstraintDegree::new(1),
    ];

    assert_eq!(NUM_CONSTRAINTS, degrees.len());

    let context = AirContext::new(trace_info, degrees, NUM_ASSERTIONS, options);

    Self {
        context,
        pub_inputs,
    }
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
    debug_assert_eq!(NUM_CONSTRAINTS, result.len());

    let current = frame.current();
    let next = frame.next();

    let hash = current[COL_HASH];
    let mal = current[COL_MAL];
    let sott = current[COL_SOTT];

    let commitment = current[COL_COMMITMENT];
    let policy_id = current[COL_POLICY];
    let nonce = current[COL_NONCE];
    let session_binding = current[COL_SESSION_BINDING];

    let table_id = current[COL_TABLE_ID];
    let table_hash = current[COL_TABLE_HASH];
    let table_s0 = current[COL_TABLE_S0];
    let table_s1 = current[COL_TABLE_S1];
    let table_s2 = current[COL_TABLE_S2];

    let b = current[COL_MATCH];
    let acc = current[COL_ACC];
    let next_acc = next[COL_ACC];

    let mut idx = 0;

    // --------------------------------------------------------------------------------------------
    // 1. Carry constraints for private claims and public statement
    // --------------------------------------------------------------------------------------------

    result[idx] = next[COL_HASH] - current[COL_HASH];
    idx += 1;

    result[idx] = next[COL_MAL] - current[COL_MAL];
    idx += 1;

    result[idx] = next[COL_SOTT] - current[COL_SOTT];
    idx += 1;

    result[idx] = next[COL_COMMITMENT] - current[COL_COMMITMENT];
    idx += 1;

    result[idx] = next[COL_POLICY] - current[COL_POLICY];
    idx += 1;

    result[idx] = next[COL_NONCE] - current[COL_NONCE];
    idx += 1;

    result[idx] = next[COL_SESSION_BINDING] - current[COL_SESSION_BINDING];
    idx += 1;

    // --------------------------------------------------------------------------------------------
    // 2. match flag booleanity
    // --------------------------------------------------------------------------------------------
    //
    // b in {0,1}

    result[idx] = b * (b - E::ONE);
    idx += 1;

    // --------------------------------------------------------------------------------------------
    // 3. If b = 1, disease id must match
    // --------------------------------------------------------------------------------------------

    result[idx] = b * (mal - table_id);
    idx += 1;

    // --------------------------------------------------------------------------------------------
    // 4. If b = 1, diagnosis hash must match
    // --------------------------------------------------------------------------------------------

    result[idx] = b * (hash - table_hash);
    idx += 1;

    // --------------------------------------------------------------------------------------------
    // 5. If b = 1, one of the three subcategories must match
    // --------------------------------------------------------------------------------------------

    result[idx] = b * (sott - table_s0) * (sott - table_s1) * (sott - table_s2);
    idx += 1;

    // --------------------------------------------------------------------------------------------
    // 6. Policy check
    // --------------------------------------------------------------------------------------------
    //
    // In this prototype:
    //
    // policy_id == sottocategoria_id
    //
    // Therefore the verifier asks for a public policy/treatment,
    // and the prover proves that the hidden subcategory corresponds to it.

    result[idx] = policy_id - sott;
    idx += 1;

    // --------------------------------------------------------------------------------------------
    // 7. Commitment opening
    // --------------------------------------------------------------------------------------------

    let computed_commitment = demo_commitment(hash, mal, sott);

    result[idx] = computed_commitment - commitment;
    idx += 1;

    // --------------------------------------------------------------------------------------------
    // 8. Session binding
    // --------------------------------------------------------------------------------------------

    let computed_session_binding =
        demo_session_binding(commitment, policy_id, nonce);

    result[idx] = computed_session_binding - session_binding;
    idx += 1;

    // --------------------------------------------------------------------------------------------
    // 9. Accumulator transition
    // --------------------------------------------------------------------------------------------
    //
    // acc_{t+1} = acc_t + b_t
    //
    // Together with:
    // acc_0 = 0
    // acc_last = 1
    //
    // this enforces that exactly one matching row exists.

    result[idx] = next_acc - acc - b;
    idx += 1;

    debug_assert_eq!(idx, NUM_CONSTRAINTS);
}

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
    let mut assertions = Vec::with_capacity(NUM_ASSERTIONS);

    // Public inputs at row 0.
    // They are carried across all rows by transition constraints.
    assertions.push(Assertion::single(
        COL_COMMITMENT,
        0,
        self.pub_inputs.commitment,
    ));

    assertions.push(Assertion::single(
        COL_POLICY,
        0,
        self.pub_inputs.policy_id,
    ));

    assertions.push(Assertion::single(
        COL_NONCE,
        0,
        self.pub_inputs.nonce,
    ));

    assertions.push(Assertion::single(
        COL_SESSION_BINDING,
        0,
        self.pub_inputs.session_binding,
    ));

    // Fix the public lookup table inside the trace.
    for row in 0..TRACE_LENGTH {
        let (id, hash, sottos) = table_row(row);

        assertions.push(Assertion::single(COL_TABLE_ID, row, id));
        assertions.push(Assertion::single(COL_TABLE_HASH, row, hash));
        assertions.push(Assertion::single(COL_TABLE_S0, row, sottos[0]));
        assertions.push(Assertion::single(COL_TABLE_S1, row, sottos[1]));
        assertions.push(Assertion::single(COL_TABLE_S2, row, sottos[2]));
    }

    // Accumulator starts at 0.
    assertions.push(Assertion::single(
        COL_ACC,
        0,
        BaseElement::ZERO,
    ));

    // Accumulator ends at 1: exactly one row matched.
    assertions.push(Assertion::single(
        COL_ACC,
        TRACE_LENGTH - 1,
        BaseElement::ONE,
    ));

    debug_assert_eq!(assertions.len(), NUM_ASSERTIONS);

    assertions
}
}

// ================================================================================================
// Prover
// ================================================================================================

type H = hashers::Blake3_256<BaseElement>;

pub struct DiagnosiProver {
    pub options: ProofOptions,
    pub pub_inputs: DiagnosiPublicInputs,
}

impl DiagnosiProver {
    pub fn new(options: ProofOptions, pub_inputs: DiagnosiPublicInputs) -> Self {
        Self {
            options,
            pub_inputs,
        }
    }
}

impl Prover for DiagnosiProver {
    type BaseField = BaseElement;
    type Air = DiagnosiAir;
    type Trace = TraceTable<BaseElement>;

    type HashFn = H;
    type RandomCoin = DefaultRandomCoin<H>;
    type VC = MerkleTree<H>;

    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, H, Self::VC>;

    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, DiagnosiAir, E>;

    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, H, Self::VC>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> DiagnosiPublicInputs {
        self.pub_inputs.clone()
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a DiagnosiAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(
            air,
            aux_rand_elements,
            composition_coefficients,
        )
    }

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

// ================================================================================================
// Benchmark helper
// ================================================================================================

fn average_duration(total: Duration, samples: u32) -> Duration {
    if samples == 0 {
        Duration::ZERO
    } else {
        total / samples
    }
}

// ================================================================================================
// Main
// ================================================================================================

fn main() -> Result<(), VerifierError> {
    // Caso valido:
    //
    // MALATTIE_BASE contiene:
    //
    // malattia_id = 3
    // hash_diagnosi = 40
    // sottocategorie = [2411, 4506, 0]
    //
    // Qui dimostriamo in ZK che:
    // - conosco hash=40, malattia=3, sottocategoria=2411;
    // - questi valori aprono il commitment pubblico;
    // - la sottocategoria soddisfa la policy pubblica 2411;
    // - la proof è legata al nonce 123456.

    let inputs = DiagnosiInputs {
        hash_diagnosi: BaseElement::new(40),
        malattia_id: BaseElement::new(3),
        sottocategoria_id: BaseElement::new(2411),
        policy_id: BaseElement::new(2411),
        nonce: BaseElement::new(123_456),
    };

    let pub_inputs = build_public_inputs(&inputs);

    println!(
        "{:^8} | {:^8} | {:^8} | {:^8} | {:^8} | {:^7} | {:^9} | {:^15} | {:^15}",
        "Queries",
        "Blowup",
        "Grinding",
        "Folding",
        "Security",
        "Runs",
        "Size (B)",
        "Avg Proving",
        "Avg Verif."
    );

    println!("{}", "-".repeat(122));

    let queries_list = [27, 32];
    let blowup_list = [16, 32];
    let grinding_list = [0, 16];
    let folding_list = [4, 8];
    let benchmark_runs = 150u32;

    for &num_queries in &queries_list {
        for &blowup_factor in &blowup_list {
            for &grinding_factor in &grinding_list {
                for &folding_factor in &folding_list {
                    let domain_size = TRACE_LENGTH * blowup_factor;

                    if num_queries >= domain_size {
                        continue;
                    }

                    let options = ProofOptions::new(
                        num_queries,
                        blowup_factor,
                        grinding_factor,
                        FieldExtension::Quadratic,
                        folding_factor,
                        31,
                        BatchingMethod::Linear,
                        BatchingMethod::Linear,
                    );

                    let security =
                        grinding_factor as u32
                            + (num_queries as u32 * blowup_factor.trailing_zeros());

                    let min_opts = AcceptableOptions::MinConjecturedSecurity(90);

                    let mut prove_total = Duration::ZERO;
                    let mut verify_total = Duration::ZERO;
                    let mut successful_runs = 0u32;
                    let mut proof_size = None;

                    for _ in 0..benchmark_runs {
                        let trace = build_trace(&inputs);

                        let prover =
                            DiagnosiProver::new(options.clone(), pub_inputs.clone());

                        let start_prove = Instant::now();

                        let proof = match prover.prove(trace) {
                            Ok(proof) => {
                                prove_total += start_prove.elapsed();
                                proof
                            }
                            Err(_) => continue,
                        };

                        let proof_bytes = proof.to_bytes();

                        if proof_size.is_none() {
                            proof_size = Some(proof_bytes.len());
                        }

                        let proof_from_bytes =
                            Proof::from_bytes(&proof_bytes).unwrap();

                        let start_verify = Instant::now();

                            
                        let verify_res =
                            verify::<
                                DiagnosiAir,
                                H,
                                DefaultRandomCoin<H>,
                                MerkleTree<H>,
                            >(
                                proof_from_bytes,
                                pub_inputs.clone(),
                                &min_opts,
                            );

                        let verify_elapsed = start_verify.elapsed();

                        if verify_res.is_ok() {
                            verify_total += verify_elapsed;
                            successful_runs += 1;
                        }
                    }

                    if successful_runs > 0 {
                        println!(
                            "{:^8} | {:^8} | {:^8} | {:^8} | {:^8} | {:^7} | {:^9} | {:^15?} | {:^15?}",
                            num_queries,
                            blowup_factor,
                            grinding_factor,
                            folding_factor,
                            security,
                            format!("{successful_runs}/{benchmark_runs}"),
                            proof_size.unwrap_or(0),
                            average_duration(prove_total, successful_runs),
                            average_duration(verify_total, successful_runs),
                        );
                    } else {
                        println!(
                            "{:^8} | {:^8} | {:^8} | {:^8} | {:^8} | {:^7} | {:^9} | {:^15} | {:^15}",
                            num_queries,
                            blowup_factor,
                            grinding_factor,
                            folding_factor,
                            security,
                            format!("0/{benchmark_runs}"),
                            proof_size.unwrap_or(0),
                            "Prove Fail",
                            "Verify Fail",
                        );
                    }
                }
            }
        }
    }

    Ok(())
}