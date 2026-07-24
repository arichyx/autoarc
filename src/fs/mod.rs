//! Filesystem-level helpers: file-type classification, path conventions, and video renaming.

mod classify;
mod paths;
mod video;

pub use classify::{FileType, get_file_type, is_type_archive, is_type_document, is_type_video};
pub(crate) use paths::rename_noreplace;
pub use paths::{create_outpath, out_dir_name, out_dir_path, relative_path};
pub use video::rename_video;
pub(crate) use video::video_rename_target;
