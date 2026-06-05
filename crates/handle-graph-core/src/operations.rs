/// Arity and type-validation helpers for the HandleGraph OperationCode surface.
use super::types::{HandleType, OperationCode, OperationViolation};

pub(super) fn expected_arity(op: OperationCode) -> usize {
    match op {
        OperationCode::Add
        | OperationCode::Sub
        | OperationCode::Eq
        | OperationCode::Lt
        | OperationCode::Lte
        | OperationCode::Gt
        | OperationCode::Gte
        | OperationCode::And
        | OperationCode::Or => 2,
        OperationCode::Not => 1,
        OperationCode::Select => 3,
    }
}

pub(super) fn validate_arity(op: OperationCode, actual: usize) -> Result<(), OperationViolation> {
    let expected = expected_arity(op);
    if actual == expected {
        Ok(())
    } else {
        Err(OperationViolation::WrongArity {
            operation_code: op,
            expected,
            actual,
        })
    }
}

/// Checks input and output types for `op`. Callers must validate arity first:
/// the `Select` arm indexes `inputs[0..=2]` directly, relying on that guarantee.
pub(super) fn validate_operation_types(
    op: OperationCode,
    inputs: &[HandleType],
    output_type: HandleType,
) -> Result<(), OperationViolation> {
    match op {
        OperationCode::Add | OperationCode::Sub => {
            require_each_input(inputs, HandleType::Suint256)?;
            require_output(output_type, HandleType::Suint256)
        }
        OperationCode::Eq
        | OperationCode::Lt
        | OperationCode::Lte
        | OperationCode::Gt
        | OperationCode::Gte => {
            require_each_input(inputs, HandleType::Suint256)?;
            require_output(output_type, HandleType::Sbool)
        }
        OperationCode::And | OperationCode::Or => {
            require_each_input(inputs, HandleType::Sbool)?;
            require_output(output_type, HandleType::Sbool)
        }
        OperationCode::Not => {
            require_each_input(inputs, HandleType::Sbool)?;
            require_output(output_type, HandleType::Sbool)
        }
        OperationCode::Select => {
            // inputs are (predicate, when_true, when_false): the predicate is
            // sbool, both branches must share a type, and the output matches it.
            require_input_at(inputs, 0, HandleType::Sbool)?;
            require_input_at(inputs, 2, inputs[1])?;
            require_output(output_type, inputs[1])
        }
    }
}

fn require_each_input(
    inputs: &[HandleType],
    expected: HandleType,
) -> Result<(), OperationViolation> {
    for (index, actual) in inputs.iter().enumerate() {
        if *actual != expected {
            return Err(OperationViolation::WrongInputHandleType {
                input_index: index,
                expected,
                actual: *actual,
            });
        }
    }
    Ok(())
}

fn require_input_at(
    inputs: &[HandleType],
    index: usize,
    expected: HandleType,
) -> Result<(), OperationViolation> {
    if inputs[index] != expected {
        return Err(OperationViolation::WrongInputHandleType {
            input_index: index,
            expected,
            actual: inputs[index],
        });
    }
    Ok(())
}

fn require_output(actual: HandleType, expected: HandleType) -> Result<(), OperationViolation> {
    if actual == expected {
        Ok(())
    } else {
        Err(OperationViolation::WrongOutputHandleType { expected, actual })
    }
}
