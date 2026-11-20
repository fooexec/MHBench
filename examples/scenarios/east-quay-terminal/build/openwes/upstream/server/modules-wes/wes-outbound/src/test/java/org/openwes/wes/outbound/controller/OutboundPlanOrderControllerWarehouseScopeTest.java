package org.openwes.wes.outbound.controller;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openwes.wes.api.outbound.IOutboundPlanOrderApi;
import org.openwes.wes.api.outbound.dto.OutboundPlanOrderDTO;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OutboundPlanOrderControllerWarehouseScopeTest {

    @Mock
    private IOutboundPlanOrderApi outboundPlanOrderApi;

    @InjectMocks
    private OutboundPlanOrderController controller;

    @Test
    void rejectsPriorityChangeForAnotherWarehouse() {
        OutboundPlanOrderDTO order = new OutboundPlanOrderDTO();
        order.setWarehouseCode("WH-OTHER");
        when(outboundPlanOrderApi.getByIds(List.of(91L))).thenReturn(List.of(order));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> controller.improvePriority(List.of(91L), 100, "WH-ALLOWED")
        );

        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
        verify(outboundPlanOrderApi, never()).improvePriority(List.of(91L), 100);
    }

    @Test
    void rejectsMissingWarehouseContext() {
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> controller.improvePriority(List.of(91L), 100, null)
        );

        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
        verify(outboundPlanOrderApi, never()).improvePriority(List.of(91L), 100);
    }
}
