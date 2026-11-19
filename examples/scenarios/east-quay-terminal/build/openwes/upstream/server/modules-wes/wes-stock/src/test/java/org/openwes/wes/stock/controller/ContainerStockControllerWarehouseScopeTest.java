package org.openwes.wes.stock.controller;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openwes.wes.api.stock.IStockApi;
import org.openwes.wes.api.stock.dto.ContainerStockDTO;
import org.openwes.wes.stock.controller.parameter.FreezeStockVO;
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
class ContainerStockControllerWarehouseScopeTest {

    @Mock
    private IStockApi stockApi;

    @InjectMocks
    private ContainerStockController controller;

    @Test
    void rejectsFreezingStockFromAnotherWarehouse() {
        FreezeStockVO request = new FreezeStockVO();
        request.setId(41L);
        request.setQty(1);
        ContainerStockDTO stock = new ContainerStockDTO();
        stock.setWarehouseCode("WH-OTHER");
        when(stockApi.getContainerStocks(List.of(41L))).thenReturn(List.of(stock));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> controller.freezeContainerStock(request, "WH-ALLOWED")
        );

        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
        verify(stockApi, never()).freezeContainerStock(41L, 1);
    }

    @Test
    void rejectsMissingWarehouseContext() {
        FreezeStockVO request = new FreezeStockVO();
        request.setId(41L);
        request.setQty(1);

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> controller.unfreezeContainerStock(request, null)
        );

        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
        verify(stockApi, never()).unfreezeContainerStock(41L, 1);
    }
}
