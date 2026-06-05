extern crate winterfell;

use std::time::{Duration, Instant};

use winterfell::{
    matrix::ColMatrix, verify, AcceptableOptions, Air, AirContext, Assertion, AuxRandElements,
    BatchingMethod, CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree, VerifierError,
};

use winterfell::crypto::{hashers, DefaultRandomCoin, MerkleTree};
use winterfell::math::{FieldElement, ToElements};
use winterfell::math::fields::f64::BaseElement;

// ================================================================================================
// Domain data
// ================================================================================================

const NUM_DISEASES: usize = 4;

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
// The trace is dynamic in the number of attributes.
// For each attribute i we reserve 9 columns:
//   0 hash_diagnosi        private witness
//   1 malattia_id          private witness
//   2 sottocategoria_id    private witness
//   3 commitment C_i       public input carried in the trace
//   4 policy_id d_i        public input carried in the trace
//   5 nonce_i              public input carried in the trace
//   6 session_binding_i    public input carried in the trace
//   7 match_i              private dynamic witness
//   8 acc_i                private dynamic witness
//
// After all attributes, we reserve 6 shared table columns:
//   table_valid, table_id, table_hash, table_s0, table_s1, table_s2

const TRACE_LENGTH: usize = 8;
const ATTR_WIDTH: usize = 9;
const TABLE_WIDTH: usize = 6;

const OFF_HASH: usize = 0;
const OFF_MAL: usize = 1;
const OFF_SOTT: usize = 2;
const OFF_COMMITMENT: usize = 3;
const OFF_POLICY: usize = 4;
const OFF_NONCE: usize = 5;
const OFF_SESSION_BINDING: usize = 6;
const OFF_MATCH: usize = 7;
const OFF_ACC: usize = 8;

const NUM_CONSTRAINTS_PER_ATTR: usize = 16;

fn attr_base(attribute_index: usize) -> usize {
    attribute_index * ATTR_WIDTH
}

fn table_base(attribute_count: usize) -> usize {
    attribute_count * ATTR_WIDTH
}

fn col_table_valid(attribute_count: usize) -> usize {
    table_base(attribute_count)
}

fn col_table_id(attribute_count: usize) -> usize {
    table_base(attribute_count) + 1
}

fn col_table_hash(attribute_count: usize) -> usize {
    table_base(attribute_count) + 2
}

fn col_table_s0(attribute_count: usize) -> usize {
    table_base(attribute_count) + 3
}

fn col_table_s1(attribute_count: usize) -> usize {
    table_base(attribute_count) + 4
}

fn col_table_s2(attribute_count: usize) -> usize {
    table_base(attribute_count) + 5
}

fn trace_width(attribute_count: usize) -> usize {
    attribute_count * ATTR_WIDTH + TABLE_WIDTH
}

fn num_assertions(attribute_count: usize) -> usize {
    // For each row: table_valid + table_id + table_hash + s0 + s1 + s2.
    // For each attribute: 4 public inputs + acc_0 + acc_last + match_last.
    TABLE_WIDTH * TRACE_LENGTH + 7 * attribute_count
}

fn num_constraints(attribute_count: usize) -> usize {
    NUM_CONSTRAINTS_PER_ATTR * attribute_count
}

// ================================================================================================
// Public and private inputs
// ================================================================================================

#[derive(Clone, Debug)]
pub struct DiagnosiAttributoPublic {
    pub commitment: BaseElement,
    pub policy_id: BaseElement,
    pub nonce: BaseElement,
    pub session_binding: BaseElement,
}

#[derive(Clone, Debug)]
pub struct DiagnosiPublicInputs {
    pub attributi: Vec<DiagnosiAttributoPublic>,
}

impl ToElements<BaseElement> for DiagnosiPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity(self.attributi.len() * 4);

        for attr in &self.attributi {
            elements.push(attr.commitment);
            elements.push(attr.policy_id);
            elements.push(attr.nonce);
            elements.push(attr.session_binding);
        }

        elements
    }
}

#[derive(Clone)]
pub struct DiagnosiAttributoInput {
    pub hash_diagnosi: BaseElement,
    pub malattia_id: BaseElement,
    pub sottocategoria_id: BaseElement,

    // In this prototype policy_id coincides with the requested treatment/subcategory.
    pub policy_id: BaseElement,

    // Public nonce generated by the verifier. It can be the same for all attributes.
    pub nonce: BaseElement,
}

#[derive(Clone)]
pub struct DiagnosiInputs {
    pub attributi: Vec<DiagnosiAttributoInput>,
}

// ================================================================================================
// Demo commitment and session binding
// ================================================================================================
//
// These functions are AIR-friendly but not cryptographic. They model the commitment opening.
// For a production or paper-strength prototype, replace them with a full hash AIR.

fn demo_commitment_base(hash: BaseElement, mal: BaseElement, sott: BaseElement) -> BaseElement {
    hash * BaseElement::new(17)
        + mal * BaseElement::new(31)
        + sott * BaseElement::new(43)
        + BaseElement::new(12_345)
}

fn demo_commitment<E: FieldElement<BaseField = BaseElement>>(hash: E, mal: E, sott: E) -> E {
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

pub fn build_public_inputs(inputs: &DiagnosiInputs) -> DiagnosiPublicInputs {
    let attributi = inputs
        .attributi
        .iter()
        .map(|attr| {
            let commitment = demo_commitment_base(
                attr.hash_diagnosi,
                attr.malattia_id,
                attr.sottocategoria_id,
            );

            let session_binding =
                demo_session_binding_base(commitment, attr.policy_id, attr.nonce);

            DiagnosiAttributoPublic {
                commitment,
                policy_id: attr.policy_id,
                nonce: attr.nonce,
                session_binding,
            }
        })
        .collect();

    DiagnosiPublicInputs { attributi }
}

// ================================================================================================
// Selector computation
// ================================================================================================

fn find_matching_disease(attr: &DiagnosiAttributoInput) -> Option<usize> {
    MALATTIE_BASE.iter().position(|&(id, hash, sottos)| {
        let sott_matches = attr.sottocategoria_id == sottos[0]
            || attr.sottocategoria_id == sottos[1]
            || attr.sottocategoria_id == sottos[2];

        attr.malattia_id == id
            && attr.hash_diagnosi == hash
            && sott_matches
            && attr.policy_id == attr.sottocategoria_id
    })
}

fn table_row(row: usize) -> (BaseElement, BaseElement, BaseElement, [BaseElement; 3]) {
    if row < NUM_DISEASES {
        let (id, hash, sottos) = MALATTIE_BASE[row];
        (BaseElement::ONE, id, hash, sottos)
    } else {
        (
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            [BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
        )
    }
}

// ================================================================================================
// Trace builder
// ================================================================================================

pub fn build_trace(inputs: &DiagnosiInputs) -> TraceTable<BaseElement> {
    let attribute_count = inputs.attributi.len();
    assert!(attribute_count > 0, "serve almeno un attributo da verificare");

    let public_inputs = build_public_inputs(inputs);

    let selected_indices: Vec<usize> = inputs
        .attributi
        .iter()
        .map(|attr| {
            find_matching_disease(attr).expect(
                "Input non valido: almeno un attributo non corrisponde alla tabella/policy",
            )
        })
        .collect();

    let mut trace = TraceTable::new(trace_width(attribute_count), TRACE_LENGTH);

    trace.fill(
        |state| {
            fill_row(0, state, inputs, &public_inputs, &selected_indices);
        },
        |step, state| {
            fill_row(step + 1, state, inputs, &public_inputs, &selected_indices);
        },
    );

    trace
}

fn fill_row(
    row: usize,
    state: &mut [BaseElement],
    inputs: &DiagnosiInputs,
    public_inputs: &DiagnosiPublicInputs,
    selected_indices: &[usize],
) {
    let attribute_count = inputs.attributi.len();

    for (i, attr) in inputs.attributi.iter().enumerate() {
        let base = attr_base(i);
        let pub_attr = &public_inputs.attributi[i];

        // Private claims: constant across the trace.
        state[base + OFF_HASH] = attr.hash_diagnosi;
        state[base + OFF_MAL] = attr.malattia_id;
        state[base + OFF_SOTT] = attr.sottocategoria_id;

        // Public statement: constant across the trace.
        state[base + OFF_COMMITMENT] = pub_attr.commitment;
        state[base + OFF_POLICY] = pub_attr.policy_id;
        state[base + OFF_NONCE] = pub_attr.nonce;
        state[base + OFF_SESSION_BINDING] = pub_attr.session_binding;

        // match_i = 1 only on the selected disease row for this attribute.
        state[base + OFF_MATCH] = if row == selected_indices[i] {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        };

        // acc_i[row] = number of matches seen before this row.
        state[base + OFF_ACC] = if row > selected_indices[i] {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        };
    }

    // Shared public lookup table row.
    let (valid, id, hash, sottos) = table_row(row);
    state[col_table_valid(attribute_count)] = valid;
    state[col_table_id(attribute_count)] = id;
    state[col_table_hash(attribute_count)] = hash;
    state[col_table_s0(attribute_count)] = sottos[0];
    state[col_table_s1(attribute_count)] = sottos[1];
    state[col_table_s2(attribute_count)] = sottos[2];
}

// ================================================================================================
// AIR
// ================================================================================================

pub struct DiagnosiAir {
    context: AirContext<BaseElement>,
    pub_inputs: DiagnosiPublicInputs,
    attribute_count: usize,
}

impl Air for DiagnosiAir {
    type BaseField = BaseElement;
    type PublicInputs = DiagnosiPublicInputs;

    fn new(
        trace_info: TraceInfo,
        pub_inputs: DiagnosiPublicInputs,
        options: ProofOptions,
    ) -> Self {
        let trace_width = trace_info.width();
        assert!(trace_width > TABLE_WIDTH, "la trace deve contenere almeno un attributo");
        assert_eq!(
            (trace_width - TABLE_WIDTH) % ATTR_WIDTH,
            0,
            "trace layout non valido: servono blocchi da 9 colonne per attributo piu' 6 colonne tabella"
        );

        let attribute_count = (trace_width - TABLE_WIDTH) / ATTR_WIDTH;
        assert_eq!(
            attribute_count,
            pub_inputs.attributi.len(),
            "numero di attributi nella trace diverso dai public inputs"
        );

        let mut degrees = Vec::with_capacity(num_constraints(attribute_count));

        for _ in 0..attribute_count {
            // 1. Carry constraints for private claims and public statement.
            degrees.push(TransitionConstraintDegree::new(1)); // hash
            degrees.push(TransitionConstraintDegree::new(1)); // malattia
            degrees.push(TransitionConstraintDegree::new(1)); // sottocategoria
            degrees.push(TransitionConstraintDegree::new(1)); // commitment
            degrees.push(TransitionConstraintDegree::new(1)); // policy
            degrees.push(TransitionConstraintDegree::new(1)); // nonce
            degrees.push(TransitionConstraintDegree::new(1)); // session binding

            // 2. match booleanity.
            degrees.push(TransitionConstraintDegree::new(2));

            // 3. match can happen only on a valid table row.
            degrees.push(TransitionConstraintDegree::new(2));

            // 4. selected row disease id match.
            degrees.push(TransitionConstraintDegree::new(2));

            // 5. selected row diagnosis hash match.
            degrees.push(TransitionConstraintDegree::new(2));

            // 6. selected row subcategory membership.
            degrees.push(TransitionConstraintDegree::new(4));

            // 7. policy check.
            degrees.push(TransitionConstraintDegree::new(1));

            // 8. commitment opening.
            degrees.push(TransitionConstraintDegree::new(1));

            // 9. session binding.
            degrees.push(TransitionConstraintDegree::new(1));

            // 10. accumulator transition.
            degrees.push(TransitionConstraintDegree::new(1));
        }

        assert_eq!(degrees.len(), num_constraints(attribute_count));

        let context = AirContext::new(
            trace_info,
            degrees,
            num_assertions(attribute_count),
            options,
        );

        Self {
            context,
            pub_inputs,
            attribute_count,
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
        debug_assert_eq!(num_constraints(self.attribute_count), result.len());

        let current = frame.current();
        let next = frame.next();

        let table_valid = current[col_table_valid(self.attribute_count)];
        let table_id = current[col_table_id(self.attribute_count)];
        let table_hash = current[col_table_hash(self.attribute_count)];
        let table_s0 = current[col_table_s0(self.attribute_count)];
        let table_s1 = current[col_table_s1(self.attribute_count)];
        let table_s2 = current[col_table_s2(self.attribute_count)];

        let mut idx = 0;

        for attribute_index in 0..self.attribute_count {
            let base = attr_base(attribute_index);

            let hash = current[base + OFF_HASH];
            let mal = current[base + OFF_MAL];
            let sott = current[base + OFF_SOTT];
            let commitment = current[base + OFF_COMMITMENT];
            let policy_id = current[base + OFF_POLICY];
            let nonce = current[base + OFF_NONCE];
            let session_binding = current[base + OFF_SESSION_BINDING];
            let b = current[base + OFF_MATCH];
            let acc = current[base + OFF_ACC];
            let next_acc = next[base + OFF_ACC];

            // 1. Carry constraints for private claims and public statement.
            result[idx] = next[base + OFF_HASH] - current[base + OFF_HASH];
            idx += 1;

            result[idx] = next[base + OFF_MAL] - current[base + OFF_MAL];
            idx += 1;

            result[idx] = next[base + OFF_SOTT] - current[base + OFF_SOTT];
            idx += 1;

            result[idx] = next[base + OFF_COMMITMENT] - current[base + OFF_COMMITMENT];
            idx += 1;

            result[idx] = next[base + OFF_POLICY] - current[base + OFF_POLICY];
            idx += 1;

            result[idx] = next[base + OFF_NONCE] - current[base + OFF_NONCE];
            idx += 1;

            result[idx] = next[base + OFF_SESSION_BINDING] - current[base + OFF_SESSION_BINDING];
            idx += 1;

            // 2. b in {0,1}.
            result[idx] = b * (b - E::ONE);
            idx += 1;

            // 3. A match cannot be placed on padding rows.
            result[idx] = b * (E::ONE - table_valid);
            idx += 1;

            // 4. If b = 1, disease id must match.
            result[idx] = b * (mal - table_id);
            idx += 1;

            // 5. If b = 1, diagnosis hash must match.
            result[idx] = b * (hash - table_hash);
            idx += 1;

            // 6. If b = 1, one of the three subcategories must match.
            result[idx] = b * (sott - table_s0) * (sott - table_s1) * (sott - table_s2);
            idx += 1;

            // 7. In this prototype: policy_id == sottocategoria_id.
            result[idx] = policy_id - sott;
            idx += 1;

            // 8. Commitment opening.
            let computed_commitment = demo_commitment(hash, mal, sott);
            result[idx] = computed_commitment - commitment;
            idx += 1;

            // 9. Session binding.
            let computed_session_binding = demo_session_binding(commitment, policy_id, nonce);
            result[idx] = computed_session_binding - session_binding;
            idx += 1;

            // 10. acc_{t+1} = acc_t + b_t.
            result[idx] = next_acc - acc - b;
            idx += 1;
        }

        debug_assert_eq!(idx, num_constraints(self.attribute_count));
    }

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        let mut assertions = Vec::with_capacity(num_assertions(self.attribute_count));

        // Public inputs at row 0. They are carried across all rows by transition constraints.
        for (i, public_attr) in self.pub_inputs.attributi.iter().enumerate() {
            let base = attr_base(i);

            assertions.push(Assertion::single(
                base + OFF_COMMITMENT,
                0,
                public_attr.commitment,
            ));
            assertions.push(Assertion::single(base + OFF_POLICY, 0, public_attr.policy_id));
            assertions.push(Assertion::single(base + OFF_NONCE, 0, public_attr.nonce));
            assertions.push(Assertion::single(
                base + OFF_SESSION_BINDING,
                0,
                public_attr.session_binding,
            ));
        }

        // Fix the public lookup table inside the trace.
        for row in 0..TRACE_LENGTH {
            let (valid, id, hash, sottos) = table_row(row);

            assertions.push(Assertion::single(
                col_table_valid(self.attribute_count),
                row,
                valid,
            ));
            assertions.push(Assertion::single(col_table_id(self.attribute_count), row, id));
            assertions.push(Assertion::single(
                col_table_hash(self.attribute_count),
                row,
                hash,
            ));
            assertions.push(Assertion::single(
                col_table_s0(self.attribute_count),
                row,
                sottos[0],
            ));
            assertions.push(Assertion::single(
                col_table_s1(self.attribute_count),
                row,
                sottos[1],
            ));
            assertions.push(Assertion::single(
                col_table_s2(self.attribute_count),
                row,
                sottos[2],
            ));
        }

        // Each attribute must have exactly one valid matching row.
        for i in 0..self.attribute_count {
            let base = attr_base(i);

            assertions.push(Assertion::single(base + OFF_ACC, 0, BaseElement::ZERO));
            assertions.push(Assertion::single(
                base + OFF_ACC,
                TRACE_LENGTH - 1,
                BaseElement::ONE,
            ));

            // Last row is padding and is not part of the transition domain; force no dummy match there.
            assertions.push(Assertion::single(
                base + OFF_MATCH,
                TRACE_LENGTH - 1,
                BaseElement::ZERO,
            ));
        }

        debug_assert_eq!(assertions.len(), num_assertions(self.attribute_count));

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
        Self { options, pub_inputs }
    }
}

impl Prover for DiagnosiProver {
    type BaseField = BaseElement;
    type Air = DiagnosiAir;
    type Trace = TraceTable<BaseElement>;

    type HashFn = H;
    type RandomCoin = DefaultRandomCoin<H>;
    type VC = MerkleTree<H>;

    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, H, Self::VC>;

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
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
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

#[derive(Clone, Copy)]
struct BenchmarkConfig {
    queries: usize,
    blowup: usize,
    grinding: u32,
    folding: usize,
}

const CONFIGS: [BenchmarkConfig; 5] = [
    BenchmarkConfig {
        queries: 27,
        blowup: 4,
        grinding: 0,
        folding: 4,
    },
    BenchmarkConfig {
        queries: 27,
        blowup: 4,
        grinding: 16,
        folding: 8,
    },
    BenchmarkConfig {
        queries: 27,
        blowup: 8,
        grinding: 0,
        folding: 4,
    },
    BenchmarkConfig {
        queries: 27,
        blowup: 8,
        grinding: 16,
        folding: 8,
    },
    BenchmarkConfig {
        queries: 32,
        blowup: 8,
        grinding: 16,
        folding: 8,
    },
];

fn build_inputs(attribute_count: usize) -> DiagnosiInputs {
    let mut attributi = Vec::with_capacity(attribute_count);

    for index in 0..attribute_count {
        let malattia = &MALATTIE_BASE[index % MALATTIE_BASE.len()];
        let sottocategorie_valide: Vec<BaseElement> = malattia
            .2
            .iter()
            .copied()
            .filter(|x| *x != BaseElement::ZERO)
            .collect();
        let sott = sottocategorie_valide[index % sottocategorie_valide.len()];

        attributi.push(DiagnosiAttributoInput {
            hash_diagnosi: malattia.1,
            malattia_id: malattia.0,
            sottocategoria_id: sott,
            policy_id: sott,
            nonce: BaseElement::new(123_456 + index as u64),
        });
    }

    DiagnosiInputs { attributi }
}

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
    let benchmark_runs = 150u32;
    let min_opts = AcceptableOptions::MinConjecturedSecurity(0);

    println!(
        "{:^6} | {:^8} | {:^8} | {:^8} | {:^8} | {:^8} | {:^9} | {:^15} | {:^15} | {:^12}",
        "Attrs",
        "Queries",
        "Blowup",
        "Grinding",
        "Folding",
        "Security",
        "Size (B)",
        "Avg Proving",
        "Avg Verif.",
        "Runs"
    );
    println!("{}", "-".repeat(126));

    for attribute_count in 1..=25 {
        let inputs = build_inputs(attribute_count);
        let pub_inputs = build_public_inputs(&inputs);

        for config in CONFIGS {
            let domain_size = TRACE_LENGTH * config.blowup;
            if config.queries >= domain_size {
                continue;
            }

            let security =
                config.grinding + (config.queries as u32 * config.blowup.trailing_zeros());
            let options = ProofOptions::new(
                config.queries,
                config.blowup,
                config.grinding,
                FieldExtension::Quadratic,
                config.folding,
                31,
                BatchingMethod::Linear,
                BatchingMethod::Linear,
            );

            let mut proof_size = None;
            let mut prove_total = Duration::ZERO;
            let mut verify_total = Duration::ZERO;
            let mut successful_runs = 0u32;

            for _ in 0..benchmark_runs {
                let trace = build_trace(&inputs);
                let prover = DiagnosiProver::new(options.clone(), pub_inputs.clone());

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

                let proof_from_bytes = Proof::from_bytes(&proof_bytes).unwrap();
                let start_verify = Instant::now();
                let verify_res = verify::<DiagnosiAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
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
                    "{:^6} | {:^8} | {:^8} | {:^8} | {:^8} | {:^8} | {:^9} | {:^15?} | {:^15?} | {:^12}",
                    attribute_count,
                    config.queries,
                    config.blowup,
                    config.grinding,
                    config.folding,
                    security,
                    proof_size.unwrap_or(0),
                    average_duration(prove_total, successful_runs),
                    average_duration(verify_total, successful_runs),
                    format!("{successful_runs}/{benchmark_runs}")
                );
            } else {
                println!(
                    "{:^6} | {:^8} | {:^8} | {:^8} | {:^8} | {:^8} | {:^9} | {:^15} | {:^15} | {:^12}",
                    attribute_count,
                    config.queries,
                    config.blowup,
                    config.grinding,
                    config.folding,
                    security,
                    "N/A",
                    "Prove Fail",
                    "Verify Fail",
                    format!("0/{benchmark_runs}")
                );
            }
        }
    }

    Ok(())
}
