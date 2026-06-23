import { createContext, useContext, type PropsWithChildren } from "react";
import { useSentinelProviderBody } from "./useSentinelProviderBody";
import { useSentinelValue } from "./hooks/useSentinelValue";
import { BackendProvider } from "./contexts/BackendContext";
import { CaptureProvider } from "./contexts/CaptureContext";
import { PacketProvider } from "./contexts/PacketContext";
import { StreamProvider } from "./contexts/StreamContext";
import { FilterProvider } from "./contexts/FilterContext";
import { AnalysisProvider } from "./contexts/AnalysisContext";

const SentinelContext = createContext(false);

export function SentinelProvider({ children }: PropsWithChildren) {
  const { backendValue, captureValue, packetValue, streamValue, filterValue, analysisValue } =
    useSentinelProviderBody();

  return (
    <SentinelContext.Provider value={true}>
      <BackendProvider value={backendValue}>
        <CaptureProvider value={captureValue}>
          <PacketProvider value={packetValue}>
            <StreamProvider value={streamValue}>
              <FilterProvider value={filterValue}>
                <AnalysisProvider value={analysisValue}>{children}</AnalysisProvider>
              </FilterProvider>
            </StreamProvider>
          </PacketProvider>
        </CaptureProvider>
      </BackendProvider>
    </SentinelContext.Provider>
  );
}

export function useSentinel() {
  const insideProvider = useContext(SentinelContext);
  if (!insideProvider) {
    throw new Error("useSentinel must be used inside SentinelProvider");
  }
  return useSentinelValue();
}
