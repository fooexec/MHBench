package org.openwes.wes.api.stocktake.event;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import org.openwes.domain.event.api.DomainEvent;

@EqualsAndHashCode(callSuper = true)
@Data
@Accessors(chain = true)
@NoArgsConstructor
public class StocktakeRecordSubmitEvent extends DomainEvent {

    @NotNull
    private Long stocktakeTaskDetailId;

    @NotNull
    private Long stocktakeTaskId;

    @NotNull
    private Long stocktakeRecordId;

    public StocktakeRecordSubmitEvent(Long stocktakeTaskDetailId, Long stocktakeTaskId, Long stocktakeRecordId) {
        super(stocktakeRecordId);
        this.stocktakeTaskDetailId = stocktakeTaskDetailId;
        this.stocktakeTaskId = stocktakeTaskId;
        this.stocktakeRecordId = stocktakeRecordId;
    }
}
