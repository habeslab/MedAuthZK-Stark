extern crate winterfell;

use winterfell::crypto::{hashers, DefaultRandomCoin, MerkleTree};
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;
use winterfell::{
    matrix::ColMatrix, verify, AcceptableOptions, Air, AirContext, Assertion, AuxRandElements,
    BatchingMethod, CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree, VerifierError,
};

const MALATTIE_BASE: [(BaseElement, BaseElement, [BaseElement; 3]); 4] = [
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

#[derive(Clone)]
pub struct DiagnosiAttributo {
    pub hash_diagnosi: BaseElement,
    pub malattia_id: BaseElement,
    pub sottocategoria_id: BaseElement,
}

#[derive(Clone)]
pub struct DiagnosiInputs {
    pub attributi: Vec<DiagnosiAttributo>,
}

pub fn build_trace(inputs: &DiagnosiInputs) -> TraceTable<BaseElement> {
    let attribute_count = inputs.attributi.len();
    assert!(attribute_count > 0, "serve almeno un attributo da verificare");

    let trace_width = attribute_count * 3 + 1;
    let trace_length = 8;
    let mut trace = TraceTable::new(trace_width, trace_length);

    trace.fill(
        |state| {
            for (index, attributo) in inputs.attributi.iter().enumerate() {
                let offset = index * 3;
                state[offset] = attributo.hash_diagnosi;
                state[offset + 1] = attributo.malattia_id;
                state[offset + 2] = attributo.sottocategoria_id;
            }
            state[trace_width - 1] = BaseElement::ZERO;
        },
        |_, state| {
            for value in state.iter_mut() {
                *value += BaseElement::new(1);
            }
        },
    );

    trace
}

pub struct DiagnosiAir {
    context: AirContext<BaseElement>,
    attribute_count: usize,
}

impl Air for DiagnosiAir {
    type BaseField = BaseElement;
    type PublicInputs = ();

    fn new(trace_info: TraceInfo, _pub_inputs: (), options: ProofOptions) -> Self {
        let trace_width = trace_info.width();
        assert!(trace_width >= 4, "la trace deve contenere almeno un attributo");
        assert_eq!(
            (trace_width - 1) % 3,
            0,
            "la trace deve contenere triple hash/id/sottocategoria piu' l'indice"
        );

        let attribute_count = (trace_width - 1) / 3;
        let degrees = vec![TransitionConstraintDegree::new(1); attribute_count];
        let context = AirContext::new(trace_info, degrees, 1, options);

        Self {
            context,
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
        let idx_column = self.attribute_count * 3;
        let idx = frame.current()[idx_column];

        for attribute_index in 0..self.attribute_count {
            let offset = attribute_index * 3;
            let hash = frame.current()[offset] - idx;
            let mal = frame.current()[offset + 1] - idx;
            let sott = frame.current()[offset + 2] - idx;

            let mut acc = E::ONE;

            for (id, hash_i, sottos) in MALATTIE_BASE.iter() {
                let id_e: E = (*id).into();
                let hash_e: E = (*hash_i).into();
                let s0: E = sottos[0].into();
                let s1: E = sottos[1].into();
                let s2: E = sottos[2].into();

                let poly =
                    (mal - id_e) * (hash - hash_e) * (sott - s0) * (sott - s1) * (sott - s2);

                acc *= poly;
            }

            result[attribute_index] = acc;
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        vec![Assertion::single(
            self.attribute_count * 3,
            0,
            BaseElement::ZERO,
        )]
    }
}

type H = hashers::Blake3_256<BaseElement>;

pub struct DiagnosiProver {
    pub options: ProofOptions,
}

impl DiagnosiProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> () {
        ()
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

fn build_inputs(attribute_count: usize) -> DiagnosiInputs {
    let mut attributi = Vec::with_capacity(attribute_count);

    for index in 0..attribute_count {
        let malattia = &MALATTIE_BASE[index % MALATTIE_BASE.len()];
        let sotto_index = index % malattia.2.len();

        attributi.push(DiagnosiAttributo {
            hash_diagnosi: malattia.1,
            malattia_id: malattia.0,
            sottocategoria_id: malattia.2[sotto_index],
        });
    }

    DiagnosiInputs { attributi }
}

fn main() -> Result<(), VerifierError> {
    println!(
        "{:^6} | {:^8} | {:^8} | {:^8} | {:^8} | {:^8} | {:^10} | {:^12}",
        "Attrs",
        "Queries",
        "Blowup",
        "Grinding",
        "Folding",
        "Security",
        "Size (B)",
        "Verify"
    );
    println!("{}", "-".repeat(100));

    let queries_list = [27, 32];
    let blowup_list = [4, 8];
    let grinding_list = [0, 16];
    let folding_list = [4, 8];
    let min_opts = AcceptableOptions::MinConjecturedSecurity(0);

    for attribute_count in 1..=50 {
        let inputs = build_inputs(attribute_count);

        for &num_queries in &queries_list {
            for &blowup_factor in &blowup_list {
                for &grinding_factor in &grinding_list {
                    for &folding_factor in &folding_list {
                        let domain_size = 8 * blowup_factor;
                        if num_queries >= domain_size {
                            continue;
                        }

                        let options = ProofOptions::new(
                            num_queries,
                            blowup_factor,
                            grinding_factor,
                            FieldExtension::None,
                            folding_factor,
                            31,
                            BatchingMethod::Linear,
                            BatchingMethod::Linear,
                        );
                        let security = grinding_factor as u32
                            + (num_queries as u32 * blowup_factor.trailing_zeros());
                        let trace = build_trace(&inputs);
                        let prover = DiagnosiProver::new(options);

                        match prover.prove(trace) {
                            Ok(proof) => {
                                let proof_bytes = proof.to_bytes();
                                let proof_size = proof_bytes.len();
                                let proofn = Proof::from_bytes(&proof_bytes).unwrap();
                                let verify_ok =
                                    verify::<DiagnosiAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
                                        proofn, (), &min_opts,
                                    )
                                    .is_ok();

                                println!(
                                    "{:^6} | {:^8} | {:^8} | {:^8} | {:^8} | {:^8} | {:^10} | {:^12}",
                                    attribute_count,
                                    num_queries,
                                    blowup_factor,
                                    grinding_factor,
                                    folding_factor,
                                    security,
                                    proof_size,
                                    if verify_ok { "OK" } else { "FAIL" }
                                );
                            }
                            Err(_) => {
                                println!(
                                    "{:^6} | {:^8} | {:^8} | {:^8} | {:^8} | {:^8} | {:^10} | {:^12}",
                                    attribute_count,
                                    num_queries,
                                    blowup_factor,
                                    grinding_factor,
                                    folding_factor,
                                    security,
                                    "N/A",
                                    "PROVE FAIL"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
