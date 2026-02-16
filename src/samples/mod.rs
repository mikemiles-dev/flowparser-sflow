pub mod counter_sample;
pub mod flow_sample;

use nom::number::complete::be_u32;
use serde::{Deserialize, Serialize};

use crate::error::SflowError;
pub use counter_sample::{CounterSample, ExpandedCounterSample};
pub use flow_sample::{ExpandedFlowSample, FlowSample};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SflowSample {
    Flow(FlowSample),
    Counter(CounterSample),
    ExpandedFlow(ExpandedFlowSample),
    ExpandedCounter(ExpandedCounterSample),
    Unknown {
        enterprise: u32,
        format: u32,
        data: Vec<u8>,
    },
}

pub fn parse_samples(
    mut input: &[u8],
    num_samples: u32,
) -> Result<(&[u8], Vec<SflowSample>), SflowError> {
    let mut samples = Vec::with_capacity(num_samples as usize);

    for _ in 0..num_samples {
        let (rest, data_format) =
            be_u32(input).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
                SflowError::Incomplete {
                    available: input.len(),
                    context: "sample data_format".to_string(),
                }
            })?;

        let enterprise = data_format >> 12;
        let format = data_format & 0xFFF;

        let (rest, sample_length) =
            be_u32(rest).map_err(|_: nom::Err<nom::error::Error<&[u8]>>| {
                SflowError::Incomplete {
                    available: rest.len(),
                    context: "sample length".to_string(),
                }
            })?;

        let sample_length = sample_length as usize;
        if rest.len() < sample_length {
            return Err(SflowError::Incomplete {
                available: rest.len(),
                context: format!("sample data (need {sample_length} bytes)"),
            });
        }

        let sample_data = &rest[..sample_length];
        let after_sample = &rest[sample_length..];

        let sample = if enterprise == 0 {
            match format {
                1 => {
                    let (_, fs) =
                        flow_sample::parse_flow_sample(sample_data).map_err(|_| {
                            SflowError::ParseError {
                                offset: 0,
                                context: "flow sample".to_string(),
                                kind: "parse failure".to_string(),
                            }
                        })?;
                    SflowSample::Flow(fs)
                }
                2 => {
                    let (_, cs) =
                        counter_sample::parse_counter_sample(sample_data).map_err(|_| {
                            SflowError::ParseError {
                                offset: 0,
                                context: "counter sample".to_string(),
                                kind: "parse failure".to_string(),
                            }
                        })?;
                    SflowSample::Counter(cs)
                }
                3 => {
                    let (_, efs) = flow_sample::parse_expanded_flow_sample(sample_data)
                        .map_err(|_| SflowError::ParseError {
                            offset: 0,
                            context: "expanded flow sample".to_string(),
                            kind: "parse failure".to_string(),
                        })?;
                    SflowSample::ExpandedFlow(efs)
                }
                4 => {
                    let (_, ecs) = counter_sample::parse_expanded_counter_sample(sample_data)
                        .map_err(|_| SflowError::ParseError {
                        offset: 0,
                        context: "expanded counter sample".to_string(),
                        kind: "parse failure".to_string(),
                    })?;
                    SflowSample::ExpandedCounter(ecs)
                }
                _ => SflowSample::Unknown {
                    enterprise,
                    format,
                    data: sample_data.to_vec(),
                },
            }
        } else {
            SflowSample::Unknown {
                enterprise,
                format,
                data: sample_data.to_vec(),
            }
        };

        samples.push(sample);
        input = after_sample;
    }

    Ok((input, samples))
}
