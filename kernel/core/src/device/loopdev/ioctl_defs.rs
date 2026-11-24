// SPDX-License-Identifier: MPL-2.0

//! Linux loop ioctl command definitions.

use super::c_types::{Info64, LegacyInfo, LoopConfigAbi};
use crate::{
    ioc,
    util::ioctl::{InData, NoData, OutData, PassByVal},
};

// Reference: <https://elixir.bootlin.com/linux/v6.18/source/include/uapi/linux/loop.h>

pub(super) type SetFd          = ioc!(LOOP_SET_FD,       0x4c00, InData<i32, PassByVal>);
pub(super) type ClearFd        = ioc!(LOOP_CLR_FD,       0x4c01, NoData);
pub(super) type SetStatus      = ioc!(LOOP_SET_STATUS,   0x4c02, InData<LegacyInfo>);
pub(super) type GetStatus      = ioc!(LOOP_GET_STATUS,   0x4c03, OutData<LegacyInfo>);
pub(super) type SetStatus64    = ioc!(LOOP_SET_STATUS64, 0x4c04, InData<Info64>);
pub(super) type GetStatus64    = ioc!(LOOP_GET_STATUS64, 0x4c05, OutData<Info64>);
pub(super) type SetCapacity    = ioc!(LOOP_SET_CAPACITY, 0x4c07, NoData);
pub(super) type Configure      = ioc!(LOOP_CONFIGURE,    0x4c0a, InData<LoopConfigAbi>);

pub(super) type ControlAdd     = ioc!(LOOP_CTL_ADD,      0x4c80, InData<i32, PassByVal>);
pub(super) type ControlRemove  = ioc!(LOOP_CTL_REMOVE,   0x4c81, InData<i32, PassByVal>);
pub(super) type ControlGetFree = ioc!(LOOP_CTL_GET_FREE, 0x4c82, NoData);
