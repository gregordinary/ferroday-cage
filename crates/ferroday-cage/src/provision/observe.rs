//! What every archive layer's observer is beside its trait: how a closure,
//! a download, a provisioning run and a bound sink each reach it.
//!
//! Each layer reports progress in events of its own, through an observer trait
//! of its own, so that a caller watching one layer matches on that layer's
//! events and implements that layer's trait. Everything around the trait is the
//! same for all three and differs only in the event type and the
//! [`ProvisionEvent`](super::ProvisionEvent) variant that carries it, so it is
//! declared once, here, by [`layer_observer!`].

/// Declares the machinery around a layer's observer trait.
///
/// The trait itself stays the layer's, written out in its module with the
/// documentation that says where that layer asks it. It must have a
/// `progress(&mut self, event)` and a `cancelled(&mut self) -> bool`, both
/// defaulted, the second to `false`. The event type must have a
/// `Fetching { url }` variant. The layer must have a
/// `provision_reporting(&mut self, &ProvisionRequest<'_>, &mut dyn Observer)`
/// method, which is the body of its [`Provisioner`](super::Provisioner)
/// implementation with the observer chosen.
///
/// Declared, in the invoking module:
///
/// - a closure taking the event is an observer that reports and never cancels;
/// - the trait object is a [`Watch`](super::Watch), reporting a fetch as the
///   layer's `Fetching` event;
/// - `Silent`, which reports nowhere and never cancels;
/// - `RunObserver`, which reports through the run's shared vocabulary and
///   takes its cancellation from the run;
/// - `ObservedRun`, which reports to a bound sink and stops when either the
///   sink or the run asks;
/// - the public `Observed`, the layer with a sink bound, its `Debug`, and its
///   `Provisioner` implementation. Its read entry points are the layer's, in an
///   `impl Observed<'_>` block of its own.
///
/// ```ignore
/// layer_observer! {
///     observer: DebianObserver,
///     event: DebianEvent,
///     shared: Debian,
///     layer: Debian,
///     field: debian,
/// }
/// ```
macro_rules! layer_observer {
    (
        observer: $Observer:ident,
        event: $Event:ident,
        shared: $Variant:ident,
        layer: $Layer:ident,
        field: $field:ident $(,)?
    ) => {
        /// A download's view of the observer: the layer's own fetch event, and
        /// its answer to whether the run should stop.
        impl $crate::provision::Watch for dyn $Observer + '_ {
            fn fetching(&mut self, url: &str) {
                self.progress($Event::Fetching { url });
            }

            fn cancelled(&mut self) -> bool {
                $Observer::cancelled(self)
            }
        }

        /// A closure is an observer that reports and never cancels.
        impl<F: FnMut($Event<'_>)> $Observer for F {
            fn progress(&mut self, event: $Event<'_>) {
                self(event);
            }
        }

        /// An observer that reports nowhere and never cancels: what an entry
        /// point the caller attached no sink to uses.
        struct Silent;

        impl $Observer for Silent {}

        /// An observer that reports nowhere of its own and takes both answers
        /// from the provisioning run: what an unobserved provisioner uses as a
        /// [`Provisioner`]($crate::provision::Provisioner).
        ///
        /// The events still reach the run's own observer, wrapped in the
        /// shared vocabulary, which is the one channel every provisioner
        /// reports through.
        struct RunObserver<'a, 'r> {
            request: &'a $crate::provision::ProvisionRequest<'r>,
        }

        impl $Observer for RunObserver<'_, '_> {
            fn progress(&mut self, event: $Event<'_>) {
                self.request
                    .report($crate::provision::ProvisionEvent::$Variant(&event));
            }

            fn cancelled(&mut self) -> bool {
                self.request.cancelled()
            }
        }

        /// An observer that reports to a sink the caller bound with `observe`
        /// and stops when either that sink or the provisioning run asks it to.
        ///
        /// The caller chose the richer, layer-specific channel for events, and
        /// the sink's own `cancelled` stops a run as it stops a resolution or a
        /// layered build. A
        /// [`Provision::observe`]($crate::provision::Provision::observe)
        /// observer can still stop a run it is not reporting on.
        struct ObservedRun<'a, 'r, 'o> {
            sink: &'o mut dyn $Observer,
            request: &'a $crate::provision::ProvisionRequest<'r>,
        }

        impl $Observer for ObservedRun<'_, '_, '_> {
            fn progress(&mut self, event: $Event<'_>) {
                self.sink.progress(event);
            }

            fn cancelled(&mut self) -> bool {
                self.sink.cancelled() || self.request.cancelled()
            }
        }

        #[doc = concat!("A [`", stringify!($Layer), "`] with a progress sink bound for one call.")]
        ///
        #[doc = concat!("Returned by [`", stringify!($Layer), "::observe`].")]
        /// It implements [`Provisioner`]($crate::provision::Provisioner), so it
        /// is what a caller hands to
        /// [`provision::ensure`]($crate::provision::ensure) when it wants
        /// progress, and it mirrors the provisioner's own entry points so a
        /// resolution or a staged layer reports too.
        pub struct Observed<'o> {
            $field: &'o mut $Layer,
            sink: &'o mut dyn $Observer,
        }

        impl ::std::fmt::Debug for Observed<'_> {
            /// Renders the provisioner being observed. The sink is a caller's
            /// closure, so it renders as its presence rather than its contents.
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.debug_struct("Observed")
                    .field(stringify!($field), &self.$field)
                    .field(
                        "sink",
                        &$crate::provision::Delegate(concat!("dyn ", stringify!($Observer))),
                    )
                    .finish()
            }
        }

        impl $crate::provision::Provisioner for Observed<'_> {
            /// Reports to the sink bound here rather than to the run's
            /// observer: the caller chose the richer, layer-specific channel by
            /// binding it. Either can stop the run: the sink through its own
            /// `cancelled`, and a
            /// [`Provision::observe`]($crate::provision::Provision::observe)
            /// observer that is not reporting on it through the run.
            fn provision(
                &mut self,
                request: &$crate::provision::ProvisionRequest<'_>,
            ) -> Result<(), $crate::provision::ProvisionError> {
                let mut observer = ObservedRun {
                    sink: self.sink,
                    request,
                };
                self.$field.provision_reporting(request, &mut observer)
            }
        }
    };
}

pub(crate) use layer_observer;
